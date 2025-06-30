package detector

import (
	"log"
	"strings"
	"sync"

	"github.com/shirou/gofile/internal/magic"
)

// TypeStats holds statistics about magic type usage for optimization
type TypeStats struct {
	TotalMatches int64
	SuccessfulMatches int64
	FailedMatches int64
	AverageOffset float64
}

// DetectorCache provides caching for frequently used patterns
type DetectorCache struct {
	mutex sync.RWMutex
	cache map[string]string  // Hash of first 32 bytes -> result
	stats map[uint8]*TypeStats // Type -> usage statistics
	maxCacheSize int
}

// NewDetectorCache creates a new detector cache
func NewDetectorCache(maxSize int) *DetectorCache {
	return &DetectorCache{
		cache: make(map[string]string),
		stats: make(map[uint8]*TypeStats),
		maxCacheSize: maxSize,
	}
}

// GetCachedResult returns cached result if available
func (dc *DetectorCache) GetCachedResult(key string) (string, bool) {
	dc.mutex.RLock()
	defer dc.mutex.RUnlock()
	
	result, exists := dc.cache[key]
	return result, exists
}

// StoreResult stores result in cache
func (dc *DetectorCache) StoreResult(key, result string) {
	dc.mutex.Lock()
	defer dc.mutex.Unlock()
	
	// Implement LRU eviction if cache is full
	if len(dc.cache) >= dc.maxCacheSize {
		// Simple eviction: remove first entry (FIFO)
		for k := range dc.cache {
			delete(dc.cache, k)
			break
		}
	}
	
	dc.cache[key] = result
}

// UpdateTypeStats updates statistics for a magic type
func (dc *DetectorCache) UpdateTypeStats(magicType uint8, success bool, offset int32) {
	dc.mutex.Lock()
	defer dc.mutex.Unlock()
	
	if dc.stats[magicType] == nil {
		dc.stats[magicType] = &TypeStats{}
	}
	
	stats := dc.stats[magicType]
	stats.TotalMatches++
	
	if success {
		stats.SuccessfulMatches++
		// Update average offset
		stats.AverageOffset = (stats.AverageOffset*float64(stats.SuccessfulMatches-1) + float64(offset)) / float64(stats.SuccessfulMatches)
	} else {
		stats.FailedMatches++
	}
}

// GetTypeStats returns statistics for a magic type
func (dc *DetectorCache) GetTypeStats(magicType uint8) *TypeStats {
	dc.mutex.RLock()
	defer dc.mutex.RUnlock()
	
	if stats, exists := dc.stats[magicType]; exists {
		// Return a copy to avoid race conditions
		return &TypeStats{
			TotalMatches: stats.TotalMatches,
			SuccessfulMatches: stats.SuccessfulMatches,
			FailedMatches: stats.FailedMatches,
			AverageOffset: stats.AverageOffset,
		}
	}
	return nil
}

// OptimizedMatchEntry performs optimized matching with caching and statistics
func (d *Detector) OptimizedMatchEntry(data []byte, entry *magic.MagicEntry, fullData []byte, cache *DetectorCache) (bool, string) {
	// Generate cache key from first 32 bytes and entry details
	var keyData []byte
	if len(data) > 32 {
		keyData = data[:32]
	} else {
		keyData = data
	}
	
	// Create a simple hash key (in production, use a proper hash function)
	cacheKey := string(keyData) + string([]byte{entry.Type, byte(entry.Offset)})
	
	// Check cache first
	if cache != nil {
		if result, exists := cache.GetCachedResult(cacheKey); exists {
			if d.options.Debug {
				log.Printf("Cache hit for type %d at offset %d", entry.Type, entry.Offset)
			}
			return result != "", result
		}
	}
	
	// Perform normal matching
	match, result := d.matchEntry(data, entry, fullData)
	
	// Update statistics
	if cache != nil {
		cache.UpdateTypeStats(entry.Type, match, entry.Offset)
		
		// Cache the result
		if match {
			cache.StoreResult(cacheKey, result)
		} else {
			cache.StoreResult(cacheKey, "")
		}
	}
	
	return match, result
}

// GetOptimizedTypeOrder returns magic types ordered by success rate for better performance
func (dc *DetectorCache) GetOptimizedTypeOrder() []uint8 {
	dc.mutex.RLock()
	defer dc.mutex.RUnlock()
	
	type typeWithRate struct {
		magicType uint8
		successRate float64
	}
	
	var types []typeWithRate
	
	for magicType, stats := range dc.stats {
		if stats.TotalMatches > 0 {
			successRate := float64(stats.SuccessfulMatches) / float64(stats.TotalMatches)
			types = append(types, typeWithRate{magicType, successRate})
		}
	}
	
	// Sort by success rate (descending)
	for i := 0; i < len(types)-1; i++ {
		for j := i + 1; j < len(types); j++ {
			if types[i].successRate < types[j].successRate {
				types[i], types[j] = types[j], types[i]
			}
		}
	}
	
	result := make([]uint8, len(types))
	for i, t := range types {
		result[i] = t.magicType
	}
	
	return result
}

// ValidateDataIntegrity performs additional validation on matched data
func (d *Detector) ValidateDataIntegrity(data []byte, entry *magic.MagicEntry, result string) bool {
	// Additional validation checks can be added here
	
	// Check for reasonable file size constraints
	if len(data) > 0 && entry.Offset >= 0 {
		// Basic sanity checks
		if int(entry.Offset) > len(data) {
			return false
		}
	}
	
	// Validate result string quality
	if len(result) == 0 {
		return false
	}
	
	// Check for corrupted descriptions (already handled in individual match functions)
	return d.isValidDescription(result)
}

// EnhancedDetectBytes provides detection with caching and optimization
func (d *Detector) EnhancedDetectBytes(data []byte, cache *DetectorCache) (string, error) {
	if len(data) == 0 {
		if d.options.Debug {
			log.Printf("ERROR: EnhancedDetectBytes received empty data")
		}
		return "empty", nil
	}

	if d.options.Debug {
		log.Printf("EnhancedDetectBytes: Processing %d bytes with caching enabled", len(data))
	}

	// Get all magic entries from database
	entries := d.database.GetEntries()

	if len(entries) == 0 {
		return "data (no magic entries loaded)", nil
	}

	// Try optimized order if cache has statistics
	var typeOrder []uint8
	if cache != nil {
		typeOrder = cache.GetOptimizedTypeOrder()
		if d.options.Debug && len(typeOrder) > 0 {
			log.Printf("Using optimized type order based on success rates")
		}
	}

	// First pass: Try optimized order if available
	if len(typeOrder) > 0 {
		for _, magicType := range typeOrder[:min(len(typeOrder), 10)] { // Top 10 most successful types
			for i, entry := range entries {
				if entry.Type != magicType {
					continue
				}
				
				if match, result := d.OptimizedMatchEntry(data, entry, data, cache); match {
					if d.options.Debug {
						log.Printf("✓ OPTIMIZED MATCH at entry %d: %s", i, result)
					}
					
					if len(strings.TrimSpace(result)) == 0 || !d.ValidateDataIntegrity(data, entry, result) {
						continue
					}
					
					return d.formatResult(result), nil
				}
			}
		}
	}

	// Fall back to normal detection if optimized approach fails
	return d.DetectBytes(data)
}

// PrintCacheStatistics outputs cache performance statistics
func (dc *DetectorCache) PrintCacheStatistics() {
	dc.mutex.RLock()
	defer dc.mutex.RUnlock()
	
	log.Printf("=== Cache Statistics ===")
	log.Printf("Cache entries: %d/%d", len(dc.cache), dc.maxCacheSize)
	
	totalMatches := int64(0)
	totalSuccesses := int64(0)
	
	for magicType, stats := range dc.stats {
		if stats.TotalMatches > 0 {
			successRate := float64(stats.SuccessfulMatches) / float64(stats.TotalMatches) * 100
			log.Printf("Type %d: %d matches, %.1f%% success, avg offset: %.1f", 
				magicType, stats.TotalMatches, successRate, stats.AverageOffset)
			
			totalMatches += stats.TotalMatches
			totalSuccesses += stats.SuccessfulMatches
		}
	}
	
	if totalMatches > 0 {
		overallSuccess := float64(totalSuccesses) / float64(totalMatches) * 100
		log.Printf("Overall: %d matches, %.1f%% success rate", totalMatches, overallSuccess)
	}
}