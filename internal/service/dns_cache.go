package service

import (
	"context"
	"net"
	"sync"
	"time"
)

// DNSCacheEntry DNS缓存条目
type DNSCacheEntry struct {
	Records   []string
	Type      string
	ExpiresAt time.Time
}

// DNSCache DNS缓存服务
type DNSCache struct {
	cache   map[string]DNSCacheEntry
	mutex   sync.RWMutex
	ttl     time.Duration
	cleaner *time.Ticker
	stop    chan bool
}

// DNSCacheConfig DNS缓存配置
type DNSCacheConfig struct {
	TTL           time.Duration // 缓存生存时间
	CleanInterval time.Duration // 清理间隔
}

// NewDNSCache 创建DNS缓存服务
func NewDNSCache(config DNSCacheConfig) *DNSCache {
	if config.TTL == 0 {
		config.TTL = 5 * time.Minute
	}
	if config.CleanInterval == 0 {
		config.CleanInterval = 10 * time.Minute
	}

	cache := &DNSCache{
		cache: make(map[string]DNSCacheEntry),
		ttl:   config.TTL,
		stop:  make(chan bool),
	}

	// 启动定期清理
	cache.cleaner = time.NewTicker(config.CleanInterval)
	go cache.cleanupLoop()

	return cache
}

// LookupMX 查询MX记录（带缓存）
func (d *DNSCache) LookupMX(ctx context.Context, domain string) ([]*net.MX, error) {
	cacheKey := "MX:" + domain
	
	// 尝试从缓存获取
	if records := d.getFromCache(cacheKey); records != nil {
		return d.parseMXRecords(records), nil
	}

	// 缓存未命中，执行DNS查询
	mxRecords, err := net.LookupMX(domain)
	if err != nil {
		return nil, err
	}

	// 转换为字符串数组并缓存
	records := make([]string, len(mxRecords))
	for i, mx := range mxRecords {
		records[i] = mx.Host
	}
	
	d.setCache(cacheKey, records, "MX")
	return mxRecords, nil
}

// LookupTXT 查询TXT记录（带缓存）
func (d *DNSCache) LookupTXT(ctx context.Context, domain string) ([]string, error) {
	cacheKey := "TXT:" + domain
	
	// 尝试从缓存获取
	if records := d.getFromCache(cacheKey); records != nil {
		return records, nil
	}

	// 缓存未命中，执行DNS查询
	txtRecords, err := net.LookupTXT(domain)
	if err != nil {
		return nil, err
	}

	d.setCache(cacheKey, txtRecords, "TXT")
	return txtRecords, nil
}

// LookupA 查询A记录（带缓存）
func (d *DNSCache) LookupA(ctx context.Context, domain string) ([]string, error) {
	cacheKey := "A:" + domain
	
	// 尝试从缓存获取
	if records := d.getFromCache(cacheKey); records != nil {
		return records, nil
	}

	// 缓存未命中，执行DNS查询
	ips, err := net.LookupHost(domain)
	if err != nil {
		return nil, err
	}

	d.setCache(cacheKey, ips, "A")
	return ips, nil
}

// LookupCNAME 查询CNAME记录（带缓存）
func (d *DNSCache) LookupCNAME(ctx context.Context, domain string) (string, error) {
	cacheKey := "CNAME:" + domain
	
	// 尝试从缓存获取
	if records := d.getFromCache(cacheKey); records != nil && len(records) > 0 {
		return records[0], nil
	}

	// 缓存未命中，执行DNS查询
	cname, err := net.LookupCNAME(domain)
	if err != nil {
		return "", err
	}

	d.setCache(cacheKey, []string{cname}, "CNAME")
	return cname, nil
}

// getFromCache 从缓存获取记录
func (d *DNSCache) getFromCache(key string) []string {
	d.mutex.RLock()
	defer d.mutex.RUnlock()

	entry, exists := d.cache[key]
	if !exists || time.Now().After(entry.ExpiresAt) {
		return nil
	}

	return entry.Records
}

// setCache 设置缓存
func (d *DNSCache) setCache(key string, records []string, recordType string) {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	d.cache[key] = DNSCacheEntry{
		Records:   records,
		Type:      recordType,
		ExpiresAt: time.Now().Add(d.ttl),
	}
}

// parseMXRecords 解析MX记录字符串为net.MX结构
func (d *DNSCache) parseMXRecords(hosts []string) []*net.MX {
	mxRecords := make([]*net.MX, len(hosts))
	for i, host := range hosts {
		mxRecords[i] = &net.MX{
			Host: host,
			Pref: 10, // 默认优先级
		}
	}
	return mxRecords
}

// cleanupLoop 定期清理过期缓存
func (d *DNSCache) cleanupLoop() {
	for {
		select {
		case <-d.cleaner.C:
			d.cleanup()
		case <-d.stop:
			d.cleaner.Stop()
			return
		}
	}
}

// cleanup 清理过期缓存条目
func (d *DNSCache) cleanup() {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	now := time.Now()
	for key, entry := range d.cache {
		if now.After(entry.ExpiresAt) {
			delete(d.cache, key)
		}
	}
}

// InvalidateCache 使指定域名的缓存失效
func (d *DNSCache) InvalidateCache(domain string) {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	// 删除该域名的所有记录类型
	recordTypes := []string{"MX", "TXT", "A", "CNAME"}
	for _, recordType := range recordTypes {
		key := recordType + ":" + domain
		delete(d.cache, key)
	}
}

// ClearCache 清空所有缓存
func (d *DNSCache) ClearCache() {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	d.cache = make(map[string]DNSCacheEntry)
}

// Stop 停止DNS缓存服务
func (d *DNSCache) Stop() {
	close(d.stop)
}

// GetCacheStats 获取缓存统计信息
func (d *DNSCache) GetCacheStats() map[string]interface{} {
	d.mutex.RLock()
	defer d.mutex.RUnlock()

	stats := make(map[string]interface{})
	stats["total_entries"] = len(d.cache)
	
	typeCount := make(map[string]int)
	expiredCount := 0
	now := time.Now()
	
	for _, entry := range d.cache {
		typeCount[entry.Type]++
		if now.After(entry.ExpiresAt) {
			expiredCount++
		}
	}
	
	stats["by_type"] = typeCount
	stats["expired_entries"] = expiredCount
	stats["ttl_seconds"] = int(d.ttl.Seconds())
	
	return stats
}

// WarmupCache 预热缓存
func (d *DNSCache) WarmupCache(domains []string) {
	ctx := context.Background()
	
	// 并行预热多个域名
	var wg sync.WaitGroup
	for _, domain := range domains {
		wg.Add(1)
		go func(domain string) {
			defer wg.Done()
			
			// 预热常用记录类型
			d.LookupMX(ctx, domain)
			d.LookupA(ctx, domain)
			d.LookupTXT(ctx, domain)
		}(domain)
	}
	
	wg.Wait()
}