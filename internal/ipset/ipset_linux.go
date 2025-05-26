//go:build linux

package ipset

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"

	"github.com/AdguardTeam/golibs/container"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/google/nftables"
)

// How to test on a real Linux machine:
//
//  1. Create nftables set: "nft add table inet fw4; nft add set inet fw4 example_set { type ipv4_addr; }"
//
//  2. Run "nft list set inet fw4 example_set". The set should be empty.
//
//  3. Add the line "example.com/4#inet#fw4#example_set" to your AdGuardHome.yaml.
//
//  4. Start AdGuardHome.
//
//  5. Make requests to example.com and its subdomains.
//
//  6. Run "nft list set inet fw4 example_set". The set should contain the resolved IP addresses.

// newManager returns a new Linux nftables ipset manager.
func newManager(ctx context.Context, conf *Config) (set Manager, err error) {
	defer func() { err = errors.Annotate(err, "ipset: %w") }()

	// Создаем соединение с nftables
	c, err := nftables.New(nftables.AsLasting())
	if err != nil {
		return nil, fmt.Errorf("creating nftables connection: %w", err)
	}

	m := &manager{
		mu: &sync.Mutex{},

		nameToIpset:    make(map[string]*nftables.Set),
		domainToIpsets: make(map[string][]*nftables.Set),

		logger: conf.Logger,
		conn:   c,

		addedIPs: container.NewMapSet[ipInIpsetEntry](),
	}

	err = m.parseIpsetConfig(ctx, conf.Lines)
	if err != nil {
		return nil, fmt.Errorf("parsing ipset config: %w", err)
	}

	m.logger.DebugContext(ctx, "nftables ipset manager initialized")

	return m, nil
}

// manager is the Linux nftables ipset manager.
type manager struct {
	// nameToIpset maps ipset names in format "4#inet#table#set" to nftables.Set
	nameToIpset    map[string]*nftables.Set
	// domainToIpsets maps domain names to their corresponding nftables sets
	domainToIpsets map[string][]*nftables.Set

	logger *slog.Logger
	conn   *nftables.Conn

	// mu protects all properties below
	mu *sync.Mutex

	// addedIPs tracks which IPs have been added to prevent duplicates
	// Only persistent sets (without timeout) are tracked
	addedIPs *container.MapSet[ipInIpsetEntry]
}

// ipInIpsetEntry represents an IP address entry in a specific ipset
type ipInIpsetEntry struct {
	ipsetName string
	// TODO(schzen): Use netip.Addr
	ipArr [net.IPv6len]byte
}

// parseIpsetConfigLine parses one ipset configuration line.
// Format: "domain1,domain2/4#inet#table#set1,4#inet#table#set2"
// Only IPv4 sets are supported (prefix "4#")
func parseIpsetConfigLine(confStr string) (hosts, ipsetNames []string, err error) {
	confStr = strings.TrimSpace(confStr)
	hostsAndNames := strings.Split(confStr, "/")
	if len(hostsAndNames) != 2 {
		return nil, nil, fmt.Errorf("invalid value %q: expected one slash", confStr)
	}

	hosts = strings.Split(hostsAndNames[0], ",")
	ipsetNames = strings.Split(hostsAndNames[1], ",")

	if len(ipsetNames) == 0 {
		return nil, nil, nil
	}

	// Валидация и очистка имен ipset
	for i := range ipsetNames {
		ipsetNames[i] = strings.TrimSpace(ipsetNames[i])
		if len(ipsetNames[i]) == 0 {
			return nil, nil, fmt.Errorf("invalid value %q: empty ipset name", confStr)
		}
	}

	// Валидация и очистка доменов
	for i := range hosts {
		hosts[i] = strings.ToLower(strings.TrimSpace(hosts[i]))
	}

	return hosts, ipsetNames, nil
}

// parseIpsetConfig parses the ipset configuration and stores nftables sets.
func (m *manager) parseIpsetConfig(ctx context.Context, ipsetConf []string) (err error) {
	for i, confStr := range ipsetConf {
		var hosts, ipsetNames []string
		hosts, ipsetNames, err = parseIpsetConfigLine(confStr)
		if err != nil {
			return fmt.Errorf("config line at idx %d(%s): %w", i, confStr, err)
		}

		var ipsets []*nftables.Set
		for _, n := range ipsetNames {
			// Парсим формат "4#inet#table#set"
			parts := strings.Split(n, "#")
			if len(parts) != 4 {
				return fmt.Errorf("parsing ipsets from config line at idx %d(l=%s,n=%s): wrong format, expected 4#inet#table#set", i, confStr, n)
			}

			// Проверяем, что это IPv4 set
			if parts[0] != "4" {
				return fmt.Errorf("parsing ipsets from config line at idx %d(l=%s,n=%s): only IPv4 sets supported (4#...)", i, confStr, n)
			}

			// Проверяем семейство таблицы
			if parts[1] != "inet" {
				return fmt.Errorf("parsing ipsets from config line at idx %d(l=%s,n=%s): only inet family supported", i, confStr, n)
			}

			tableName := parts[2]
			setName := parts[3]

			// Проверяем кэш
			set, ok := m.nameToIpset[n]
			if !ok {
				// Получаем set из nftables
				tbl := &nftables.Table{
					Family: nftables.TableFamilyINet,
					Name:   tableName,
				}

				set, err = m.conn.GetSetByName(tbl, setName)
				if err != nil {
					return fmt.Errorf("getting ipset from config line at idx %d(l=%s,n=%s): %w", i, confStr, n, err)
				}

				// Проверяем тип set - должен быть IPv4
				if set.KeyType != nftables.TypeIPAddr {
					return fmt.Errorf("got ipset from config line at idx %d(l=%s,n=%s): wrong type, expected ipv4_addr", i, confStr, n)
				}

				m.nameToIpset[n] = set
				m.logger.DebugContext(ctx, "loaded nftables set",
					"config_line", confStr,
					"hosts", hosts,
					"set_name", n,
					"table", tableName,
					"set", setName,
				)
			}

			ipsets = append(ipsets, set)
		}

		// Связываем домены с sets
		for _, host := range hosts {
			m.domainToIpsets[host] = append(m.domainToIpsets[host], ipsets...)
		}
	}

	return nil
}

// lookupHost finds the nftables sets for the host, taking subdomain wildcards into account.
func (m *manager) lookupHost(host string) (sets []*nftables.Set) {
	// Поиск подходящих ipset начиная с наиболее специфичного домена
	// Можно использовать trie, но простое решение достаточно эффективно:
	// ~10 ns для TLD + SLD vs. ~140 ns для 10 поддоменов на AMD Ryzen 7 PRO 4750U
	for i := 0; ; i++ {
		host = host[i:]
		sets = m.domainToIpsets[host]
		if sets != nil {
			return sets
		}

		i = strings.Index(host, ".")
		if i == -1 {
			break
		}
	}

	// Проверяем корневой catch-all
	return m.domainToIpsets[""]
}

// addIPs adds IPv4 addresses to the nftables set.
func (m *manager) addIPs(host string, set *nftables.Set, ips []net.IP) (n int, err error) {
	if len(ips) == 0 {
		return 0, nil
	}

	var elements []nftables.SetElement
	var newAddedEntries []ipInIpsetEntry

	for _, ip := range ips {
		// Создаем ключ для отслеживания добавленных IP
		e := ipInIpsetEntry{
			ipsetName: fmt.Sprintf("4#inet#%s#%s", set.Table.Name, set.Name),
		}
		copy(e.ipArr[:], ip.To16())

		// Пропускаем уже добавленные IP
		if m.addedIPs.Has(e) {
			continue
		}

		// Создаем элемент для добавления в set
		// Для IPv4 используем To4()
		ipv4 := ip.To4()
		if ipv4 == nil {
			continue // Пропускаем не-IPv4 адреса
		}

		elements = append(elements, nftables.SetElement{
			Key: []byte(ipv4),
		})
		newAddedEntries = append(newAddedEntries, e)
	}

	n = len(elements)
	if n == 0 {
		return 0, nil
	}

	// Добавляем элементы в set
	err = m.conn.SetAddElements(set, elements)
	if err != nil {
		return 0, fmt.Errorf("adding %q%v to set %q: %w", host, ips, set.Name, err)
	}

	// Применяем изменения
	err = m.conn.Flush()
	if err != nil {
		return 0, fmt.Errorf("flushing changes for %q%v to set %q: %w", host, ips, set.Name, err)
	}

	// Добавляем в кэш только после успешного добавления
	// Только для persistent sets (без timeout)
	for _, e := range newAddedEntries {
		set := m.nameToIpset[e.ipsetName]
		if !set.HasTimeout {
			m.addedIPs.Add(e)
		}
	}

	return n, nil
}

// addToSets adds IP addresses to the corresponding nftables sets.
func (m *manager) addToSets(
	ctx context.Context,
	host string,
	ip4s []net.IP,
	ip6s []net.IP,
	sets []*nftables.Set,
) (n int, err error) {
	for _, set := range sets {
		var nn int

		// Поддерживаем только IPv4 sets
		switch set.KeyType {
		case nftables.TypeIPAddr:
			nn, err = m.addIPs(host, set, ip4s)
			if err != nil {
				return n, err
			}
		case nftables.TypeIP6Addr:
			// IPv6 не поддерживается в этой версии
			m.logger.DebugContext(ctx, "skipping IPv6 set (not supported)",
				"set_name", set.Name,
				"set_type", set.KeyType,
			)
			continue
		default:
			return n, fmt.Errorf("set %q has unexpected type %q", set.Name, set.KeyType)
		}

		m.logger.DebugContext(ctx, "added ips to nftables set",
			"ips_added", nn,
			"ip4s", ip4s,
			"set_name", set.Name,
			"set_type", set.KeyType,
		)

		n += nn
	}

	return n, nil
}

// Add implements the [Manager] interface for *manager.
func (m *manager) Add(ctx context.Context, host string, ip4s, ip6s []net.IP) (n int, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	sets := m.lookupHost(host)
	if len(sets) == 0 {
		return 0, nil
	}

	m.logger.DebugContext(ctx, "found nftables sets for host",
		"host", host,
		"sets_count", len(sets),
	)

	return m.addToSets(ctx, host, ip4s, ip6s, sets)
}

// Close implements the [Manager] interface for *manager.
func (m *manager) Close() (err error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Закрываем соединение с nftables
	err = m.conn.CloseLasting()
	if err != nil {
		return errors.Annotate(err, "closing nftables connection: %w")
	}

	return nil
}
