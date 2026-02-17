# Domain 10: Caching
> **Số practices:** 8 | 🔴 2 | 🟠 3 | 🟡 3
> **Trọng số:** ×1

---

## 10.01 - @Cacheable / @CacheEvict cho read-heavy data 🟠

### Metadata
- **ID:** `CACHE-001`
- **Mức độ:** 🟠 KHUYẾN NGHỊ
- **Lý do:** Giảm 70-90% database queries, tăng throughput, giảm latency
- **Trade-off:** Stale data risk, memory overhead, complexity tăng

### Tại sao?

**Vấn đề:**
- Query database mỗi request → latency cao (50-200ms/query)
- Read-heavy APIs (product catalog, user profile) gây database bottleneck
- Scaling database đắt hơn scaling cache (Redis) rất nhiều

**Giải pháp:**
- `@Cacheable` tự động cache kết quả method
- `@CacheEvict` xóa cache khi data thay đổi
- `@CachePut` update cache mà không skip method execution

**Khi nào dùng:**
- ✅ Data ít thay đổi (categories, settings, product details)
- ✅ Read:Write ratio > 10:1
- ✅ Query phức tạp (joins, aggregations)
- ❌ Real-time data (stock prices, live chat)
- ❌ Personalized data (cart, recommendations) → dùng session cache

### ✅ Cách đúng

```java
// ===== Config: CacheConfig.java =====
@Configuration
@EnableCaching
public class CacheConfig {

  @Bean
  public CacheManager cacheManager(RedisConnectionFactory redisConnectionFactory) {
    // TTL cho từng cache riêng biệt
    Map<String, RedisCacheConfiguration> cacheConfigs = Map.of(
      "products", RedisCacheConfiguration.defaultCacheConfig()
        .entryTtl(Duration.ofHours(1))
        .serializeValuesWith(RedisSerializationContext.SerializationPair
          .fromSerializer(new GenericJackson2JsonRedisSerializer())),

      "categories", RedisCacheConfiguration.defaultCacheConfig()
        .entryTtl(Duration.ofDays(1)), // Categories ít thay đổi

      "userProfiles", RedisCacheConfiguration.defaultCacheConfig()
        .entryTtl(Duration.ofMinutes(15)) // User data đổi thường xuyên hơn
    );

    return RedisCacheManager.builder(redisConnectionFactory)
      .cacheDefaults(RedisCacheConfiguration.defaultCacheConfig()
        .entryTtl(Duration.ofMinutes(10))) // Default TTL
      .withInitialCacheConfigurations(cacheConfigs)
      .build();
  }
}

// ===== Service: ProductService.java =====
@Service
@Slf4j
public class ProductService {

  @Autowired
  private ProductRepository productRepository;

  // Cache với key = productId
  @Cacheable(value = "products", key = "#productId", unless = "#result == null")
  public ProductDto getProduct(Long productId) {
    log.info("Cache MISS - Querying DB for product: {}", productId);
    return productRepository.findById(productId)
      .map(this::toDto)
      .orElse(null);
  }

  // Cache với composite key
  @Cacheable(
    value = "products",
    key = "#categoryId + ':' + #page + ':' + #size",
    condition = "#page < 10" // Chỉ cache 10 trang đầu
  )
  public Page<ProductDto> getProductsByCategory(
    Long categoryId,
    int page,
    int size
  ) {
    log.info("Cache MISS - Querying products for category: {}", categoryId);
    Pageable pageable = PageRequest.of(page, size);
    return productRepository.findByCategoryId(categoryId, pageable)
      .map(this::toDto);
  }

  // Cache với SpEL expression
  @Cacheable(
    value = "products",
    key = "T(String).format('%s:%s', #filter.brand, #filter.priceRange)",
    unless = "#result.isEmpty()"
  )
  public List<ProductDto> searchProducts(ProductFilter filter) {
    log.info("Cache MISS - Searching products with filter: {}", filter);
    return productRepository.findByFilter(filter)
      .stream()
      .map(this::toDto)
      .toList();
  }

  // Evict cache khi update
  @CacheEvict(value = "products", key = "#productId")
  public ProductDto updateProduct(Long productId, UpdateProductRequest request) {
    Product product = productRepository.findById(productId)
      .orElseThrow(() -> new NotFoundException("Product not found"));

    product.setName(request.name());
    product.setPrice(request.price());
    Product saved = productRepository.save(product);

    log.info("Cache EVICTED for product: {}", productId);
    return toDto(saved);
  }

  // Evict toàn bộ cache của category khi thêm product mới
  @CacheEvict(value = "products", allEntries = true)
  public ProductDto createProduct(CreateProductRequest request) {
    Product product = Product.builder()
      .name(request.name())
      .price(request.price())
      .categoryId(request.categoryId())
      .build();

    Product saved = productRepository.save(product);
    log.info("All product caches EVICTED due to new product creation");
    return toDto(saved);
  }

  // CachePut: luôn execute method VÀ update cache
  @CachePut(value = "products", key = "#result.id")
  public ProductDto refreshProduct(Long productId) {
    log.info("Refreshing cache for product: {}", productId);
    return productRepository.findById(productId)
      .map(this::toDto)
      .orElse(null);
  }

  private ProductDto toDto(Product product) {
    return ProductDto.builder()
      .id(product.getId())
      .name(product.getName())
      .price(product.getPrice())
      .build();
  }
}

// ===== DTO: ProductDto.java =====
@Builder
public record ProductDto(
  Long id,
  String name,
  BigDecimal price
) implements Serializable {
  // Implement Serializable để serialize vào Redis
}
```

### ❌ Cách sai

```java
// ❌ SAI 1: Không có TTL → memory leak
@Cacheable(value = "products", key = "#id")
public ProductDto getProduct(Long id) {
  // Cache sẽ tồn tại mãi mãi, gây OutOfMemoryError
}

// ❌ SAI 2: Cache key không unique → collision
@Cacheable(value = "products", key = "#page")
public Page<ProductDto> getProducts(int page, int size, String category) {
  // Key chỉ có page → các category khác nhau cùng page sẽ trả về data sai
}

// ❌ SAI 3: Quên evict cache khi update
public ProductDto updateProduct(Long id, UpdateProductRequest request) {
  Product product = productRepository.findById(id).orElseThrow();
  product.setName(request.name());
  productRepository.save(product);
  // Cache cũ vẫn còn → user thấy data cũ
  return toDto(product);
}

// ❌ SAI 4: Cache data nhạy cảm (passwords, tokens)
@Cacheable(value = "users", key = "#userId")
public UserDto getUser(Long userId) {
  // Nếu cache bị leak → lộ password hash, token
}

// ❌ SAI 5: Cache exception/null
@Cacheable(value = "products", key = "#id")
public ProductDto getProduct(Long id) {
  // Nếu throw exception → cache null → mọi request sau trả null
  return productRepository.findById(id)
    .orElseThrow(() -> new NotFoundException("Product not found"));
}
// FIX: Thêm unless = "#result == null"

// ❌ SAI 6: Không implement Serializable cho DTO
public class ProductDto { // Thiếu implements Serializable
  private Long id;
  private String name;
  // Redis serialize sẽ fail
}

// ❌ SAI 7: Self-invocation không trigger cache
@Service
public class ProductService {

  @Cacheable("products")
  public ProductDto getProduct(Long id) {
    return productRepository.findById(id).map(this::toDto).orElse(null);
  }

  public ProductDto getProductInternal(Long id) {
    // ❌ Gọi method trong cùng class → Spring AOP không intercept
    return this.getProduct(id); // Cache KHÔNG hoạt động
  }
}
// FIX: Inject ProductService vào chính nó (self-injection) hoặc dùng @Lazy
```

### Phát hiện

**Regex patterns:**
```regex
# Thiếu TTL config
@Cacheable.*\n(?!.*entryTtl)

# Cache key đơn giản (chỉ 1 param)
@Cacheable.*key\s*=\s*"#\w+"[^+:]*\)

# Thiếu unless/condition
@Cacheable(?!.*unless)(?!.*condition).*\)

# Method có @Cacheable nhưng không có @CacheEvict tương ứng
public.*update.*\{(?!.*@CacheEvict)

# DTO không implement Serializable
(class|record)\s+\w+Dto(?!.*implements\s+Serializable)
```

**Checklist:**
```java
// 1. Config có TTL cho tất cả cache?
@Bean
public CacheManager cacheManager() {
  return RedisCacheManager.builder()
    .cacheDefaults(config.entryTtl(Duration.ofMinutes(10))) // ✅
    .build();
}

// 2. Cache key đủ unique?
@Cacheable(key = "#id + ':' + #locale + ':' + #version") // ✅

// 3. Có unless để tránh cache null/exception?
@Cacheable(unless = "#result == null || #result.isEmpty()") // ✅

// 4. Write operations có evict cache?
@CacheEvict(value = "products", key = "#id") // ✅
public void updateProduct(Long id) { }

// 5. DTO có Serializable?
public record ProductDto(...) implements Serializable { } // ✅

// 6. Tránh cache data nhạy cảm?
@Cacheable("users")
public UserDto getUser(Long id) {
  return UserDto.builder()
    .id(user.getId())
    .email(user.getEmail())
    // ✅ KHÔNG trả password, token, creditCard
    .build();
}

// 7. Test cache behavior?
@Test
void testCacheHit() {
  productService.getProduct(1L); // Cache MISS
  productService.getProduct(1L); // Cache HIT
  verify(productRepository, times(1)).findById(1L); // ✅ Chỉ query 1 lần
}
```

---

## 10.02 - Cache key strategy rõ ràng (tránh collision) 🟠

### Metadata
- **ID:** `CACHE-002`
- **Mức độ:** 🟠 KHUYẾN NGHỊ
- **Lý do:** Cache collision gây trả về data sai → critical bug
- **Trade-off:** Key phức tạp → dài hơn → memory overhead (nhỏ)

### Tại sao?

**Vấn đề:**
- Key đơn giản (`#id`) → collision khi query khác nhau cùng param
- Example: `getProduct(1, locale=EN)` và `getProduct(1, locale=JP)` cùng key `1`
- Multi-tenant: tenant A thấy data của tenant B
- Pagination: page 1 size 10 vs page 1 size 20 → cùng key `1`

**Giải pháp:**
- Composite key: `tenantId:entityId:locale:version`
- Prefix theo domain: `product:1`, `user:1` (tránh ID trùng)
- Hash key nếu quá dài (>100 chars)

### ✅ Cách đúng

```java
// ===== KeyGenerator: CustomKeyGenerator.java =====
@Component("customKeyGenerator")
public class CustomKeyGenerator implements KeyGenerator {

  @Override
  public Object generate(Object target, Method method, Object... params) {
    // Tạo key format: ClassName.methodName(param1,param2,...)
    String className = target.getClass().getSimpleName();
    String methodName = method.getName();
    String paramsKey = Arrays.stream(params)
      .map(param -> param == null ? "null" : param.toString())
      .collect(Collectors.joining(","));

    String rawKey = String.format("%s.%s(%s)", className, methodName, paramsKey);

    // Hash nếu key quá dài
    if (rawKey.length() > 100) {
      return DigestUtils.md5DigestAsHex(rawKey.getBytes(StandardCharsets.UTF_8));
    }

    return rawKey;
  }
}

// ===== Service Examples =====
@Service
public class ProductService {

  // ✅ Composite key với nhiều params
  @Cacheable(
    value = "products",
    key = "#tenantId + ':' + #productId + ':' + #locale"
  )
  public ProductDto getProduct(Long tenantId, Long productId, String locale) {
    // Key example: "100:50:en_US"
  }

  // ✅ Prefix theo domain
  @Cacheable(
    value = "entities",
    key = "'product:' + #id" // product:1 vs user:1 → khác nhau
  )
  public ProductDto getProductById(Long id) { }

  // ✅ Include all pagination params
  @Cacheable(
    value = "products",
    key = "#categoryId + ':page:' + #page + ':size:' + #size + ':sort:' + #sort"
  )
  public Page<ProductDto> getProducts(
    Long categoryId,
    int page,
    int size,
    String sort
  ) {
    // Key: "10:page:0:size:20:sort:name"
  }

  // ✅ Object param → use custom KeyGenerator
  @Cacheable(
    value = "products",
    keyGenerator = "customKeyGenerator"
  )
  public List<ProductDto> searchProducts(ProductSearchFilter filter) {
    // Key: ProductService.searchProducts(ProductSearchFilter{brand=Nike,minPrice=100,...})
  }

  // ✅ SpEL với nested object
  @Cacheable(
    value = "products",
    key = "#filter.tenantId + ':' + #filter.brand + ':' + #filter.priceRange.min + '-' + #filter.priceRange.max"
  )
  public List<ProductDto> search(ProductFilter filter) {
    // Key: "100:Nike:50-200"
  }

  // ✅ Hash long key
  @Cacheable(
    value = "reports",
    key = "T(org.springframework.util.DigestUtils).md5DigestAsHex((#params.toString()).getBytes())"
  )
  public ReportDto generateReport(ReportParams params) {
    // Key: md5 hash của params.toString()
  }

  // ✅ Version-aware cache key
  @Cacheable(
    value = "products",
    key = "'v' + @appConfig.cacheVersion + ':' + #id"
  )
  public ProductDto getProduct(Long id) {
    // Key: "v2:100" → bump version để invalidate all cache
  }

  // ✅ Multi-tenant với security context
  @Cacheable(
    value = "users",
    key = "T(org.springframework.security.core.context.SecurityContextHolder).getContext().getAuthentication().getName() + ':' + #userId"
  )
  public UserDto getUser(Long userId) {
    // Key: "admin@example.com:100"
  }
}

// ===== Config: AppConfig.java =====
@Configuration
@ConfigurationProperties(prefix = "app")
@Data
public class AppConfig {
  private int cacheVersion = 1; // Bump để invalidate all cache
}
```

### ❌ Cách sai

```java
// ❌ SAI 1: Key chỉ có 1 param (thiếu locale, tenant, version)
@Cacheable(value = "products", key = "#productId")
public ProductDto getProduct(Long tenantId, Long productId, String locale) {
  // Tenant A locale EN vs Tenant B locale JP → cùng key → SAI
}

// ❌ SAI 2: Pagination key thiếu size/sort
@Cacheable(value = "products", key = "#page")
public Page<ProductDto> getProducts(int page, int size, String sort) {
  // page=1, size=10 vs page=1, size=20 → cùng key "1"
}

// ❌ SAI 3: Object param không override toString()
@Cacheable(value = "products", key = "#filter")
public List<ProductDto> search(ProductFilter filter) {
  // Key = filter.toString() = "ProductFilter@a3f5b" (hashCode) → không stable
}

// ❌ SAI 4: Không prefix theo domain
@Cacheable(value = "cache", key = "#id")
public ProductDto getProduct(Long id) { }

@Cacheable(value = "cache", key = "#id")
public UserDto getUser(Long id) { }
// getProduct(1) và getUser(1) → cùng key "1" → collision

// ❌ SAI 5: Key dài không hash
@Cacheable(
  value = "reports",
  key = "#p1 + #p2 + #p3 + ... + #p50" // Key > 500 chars → memory waste
)
public ReportDto generate(...50 params) { }

// ❌ SAI 6: Null-unsafe key
@Cacheable(value = "products", key = "#categoryId + ':' + #brandId")
public List<ProductDto> getProducts(Long categoryId, Long brandId) {
  // brandId = null → key = "10:null" (String) vs null (object) → inconsistent
}
// FIX: key = "#categoryId + ':' + (#brandId != null ? #brandId : 'all')"

// ❌ SAI 7: Multi-tenant không include tenantId
@Cacheable(value = "users", key = "#userId")
public UserDto getUser(Long userId) {
  Long tenantId = TenantContext.getCurrentTenantId();
  // Tenant A thấy data của Tenant B → CRITICAL BUG
}
```

### Phát hiện

**Regex patterns:**
```regex
# Key chỉ có 1 param đơn giản
@Cacheable.*key\s*=\s*"#\w+"[^\+:]*\)

# Pagination key thiếu size/sort
@Cacheable.*key.*page(?!.*size)

# Object param không dùng keyGenerator
@Cacheable.*key\s*=\s*"#\w+Filter"(?!.*keyGenerator)

# Multi-tenant method thiếu tenantId trong key
@Cacheable(?=.*key)(?!.*tenantId).*getTenant|getUser|getProduct

# Key dài không hash
@Cacheable.*key.*\+.*\+.*\+.*\+.*\+.*\+ # 6+ concatenations
```

**Checklist:**
```java
// 1. Key có đủ tất cả discriminator params?
@Cacheable(key = "#tenantId + ':' + #id + ':' + #locale + ':' + #version") // ✅

// 2. Pagination key đầy đủ?
@Cacheable(key = "#page + ':' + #size + ':' + #sort") // ✅

// 3. Object param dùng keyGenerator?
@Cacheable(keyGenerator = "customKeyGenerator") // ✅

// 4. Prefix theo domain?
@Cacheable(key = "'product:' + #id") // ✅

// 5. Hash nếu key > 100 chars?
if (key.length() > 100) return md5(key); // ✅

// 6. Null-safe?
key = "#id + ':' + (#category != null ? #category : 'all')" // ✅

// 7. Test cache isolation?
@Test
void testCacheIsolation() {
  productService.getProduct(tenant1, 1L, "en"); // Cache MISS
  productService.getProduct(tenant2, 1L, "en"); // Cache MISS (khác tenant)
  verify(repo, times(2)).findById(1L); // ✅ 2 queries
}
```

---

## 10.03 - TTL (Time-To-Live) cho mọi cache entry 🔴

### Metadata
- **ID:** `CACHE-003`
- **Mức độ:** 🔴 BẮT BUỘC
- **Lý do:** Không có TTL → memory leak → OutOfMemoryError
- **Trade-off:** TTL ngắn → cache miss nhiều, TTL dài → stale data

### Tại sao?

**Vấn đề:**
- Cache không expire → memory tăng không giới hạn
- Stale data tồn tại mãi → business logic sai
- Redis maxmemory-policy noeviction → write fail khi đầy

**Giải pháp:**
- Default TTL cho tất cả cache (10-60 phút)
- Custom TTL theo data type:
  - Static data (categories): 1 ngày - 1 tuần
  - Dynamic data (user profile): 5-15 phút
  - Real-time data: KHÔNG cache hoặc < 1 phút

### ✅ Cách đúng

```java
// ===== Config: CacheConfig.java =====
@Configuration
@EnableCaching
public class CacheConfig {

  @Bean
  public RedisCacheManager cacheManager(RedisConnectionFactory factory) {
    // Default config cho tất cả cache
    RedisCacheConfiguration defaultConfig = RedisCacheConfiguration
      .defaultCacheConfig()
      .entryTtl(Duration.ofMinutes(10)) // ✅ Default TTL 10 phút
      .serializeKeysWith(RedisSerializationContext.SerializationPair
        .fromSerializer(new StringRedisSerializer()))
      .serializeValuesWith(RedisSerializationContext.SerializationPair
        .fromSerializer(new GenericJackson2JsonRedisSerializer()))
      .disableCachingNullValues(); // Không cache null

    // Custom TTL cho từng cache
    Map<String, RedisCacheConfiguration> cacheConfigs = Map.of(
      // Static data - TTL dài
      "categories", defaultConfig.entryTtl(Duration.ofDays(7)),
      "countries", defaultConfig.entryTtl(Duration.ofDays(30)),
      "appSettings", defaultConfig.entryTtl(Duration.ofHours(24)),

      // Semi-static data
      "products", defaultConfig.entryTtl(Duration.ofHours(1)),
      "productCatalog", defaultConfig.entryTtl(Duration.ofMinutes(30)),

      // Dynamic data - TTL ngắn
      "userProfiles", defaultConfig.entryTtl(Duration.ofMinutes(15)),
      "userSessions", defaultConfig.entryTtl(Duration.ofMinutes(30)),
      "shoppingCarts", defaultConfig.entryTtl(Duration.ofHours(2)),

      // Real-time data - TTL rất ngắn
      "stockPrices", defaultConfig.entryTtl(Duration.ofSeconds(30)),
      "onlineUsers", defaultConfig.entryTtl(Duration.ofMinutes(1))
    );

    return RedisCacheManager.builder(factory)
      .cacheDefaults(defaultConfig)
      .withInitialCacheConfigurations(cacheConfigs)
      .transactionAware() // Cache operations trong transaction
      .build();
  }

  // ===== Config cho Redis maxmemory policy =====
  @Bean
  public RedisTemplate<String, Object> redisTemplate(
    RedisConnectionFactory factory
  ) {
    RedisTemplate<String, Object> template = new RedisTemplate<>();
    template.setConnectionFactory(factory);

    // Serialize keys as strings
    template.setKeySerializer(new StringRedisSerializer());
    template.setHashKeySerializer(new StringRedisSerializer());

    // Serialize values as JSON
    GenericJackson2JsonRedisSerializer serializer =
      new GenericJackson2JsonRedisSerializer();
    template.setValueSerializer(serializer);
    template.setHashValueSerializer(serializer);

    return template;
  }
}

// ===== application.yml =====
/*
spring:
  redis:
    host: localhost
    port: 6379
    timeout: 2000ms
    lettuce:
      pool:
        max-active: 8
        max-idle: 8
        min-idle: 2
        max-wait: 2000ms
  cache:
    type: redis
    redis:
      time-to-live: 600000 # Default 10 phút (milliseconds)
      cache-null-values: false
      use-key-prefix: true
      key-prefix: "myapp:"

# Redis maxmemory policy (config trong redis.conf)
# maxmemory 1gb
# maxmemory-policy allkeys-lru # LRU eviction khi đầy
*/

// ===== Service: Dynamic TTL =====
@Service
public class CacheService {

  @Autowired
  private CacheManager cacheManager;

  // Dynamic TTL dựa trên business logic
  public void cacheWithDynamicTtl(String cacheName, String key, Object value, Duration ttl) {
    Cache cache = cacheManager.getCache(cacheName);
    if (cache != null) {
      // Với Spring Boot 3.x + Redis, cần dùng RedisTemplate để set custom TTL
      RedisCache redisCache = (RedisCache) cache;
      redisCache.put(key, value);

      // Set TTL manually (nếu cần override default)
      // Cần inject RedisTemplate
    }
  }

  // Cache với conditional TTL
  public void cacheUser(Long userId, UserDto user) {
    Duration ttl = user.isPremium()
      ? Duration.ofHours(1)  // Premium user cache lâu hơn
      : Duration.ofMinutes(15); // Free user cache ngắn

    cacheWithDynamicTtl("users", userId.toString(), user, ttl);
  }
}

// ===== Service: TTL-aware caching =====
@Service
public class ProductService {

  @Autowired
  private ProductRepository productRepository;

  // Cache với TTL trong annotation (config-driven)
  @Cacheable(value = "products", key = "#id")
  public ProductDto getProduct(Long id) {
    // TTL = 1 hour (theo config)
    return productRepository.findById(id)
      .map(this::toDto)
      .orElse(null);
  }

  // Manual cache với custom TTL
  @Autowired
  private RedisTemplate<String, Object> redisTemplate;

  public void cacheProductWithCustomTtl(Long id, ProductDto product, long ttlMinutes) {
    String key = "product:" + id;
    redisTemplate.opsForValue().set(key, product, Duration.ofMinutes(ttlMinutes));
  }

  // Get với fallback nếu expired
  public ProductDto getProductWithFallback(Long id) {
    String key = "product:" + id;
    ProductDto cached = (ProductDto) redisTemplate.opsForValue().get(key);

    if (cached != null) {
      return cached;
    }

    // Cache miss → query DB
    ProductDto fresh = productRepository.findById(id)
      .map(this::toDto)
      .orElse(null);

    if (fresh != null) {
      redisTemplate.opsForValue().set(key, fresh, Duration.ofHours(1));
    }

    return fresh;
  }
}

// ===== Monitoring: Cache TTL metrics =====
@Component
public class CacheMetrics {

  @Autowired
  private RedisTemplate<String, Object> redisTemplate;

  @Scheduled(fixedRate = 60000) // Check mỗi phút
  public void monitorCacheTtl() {
    Set<String> keys = redisTemplate.keys("myapp:*");

    if (keys != null) {
      keys.forEach(key -> {
        Long ttl = redisTemplate.getExpire(key, TimeUnit.SECONDS);

        if (ttl != null && ttl == -1) {
          // TTL = -1 → key không expire → WARNING
          log.warn("Cache key without TTL detected: {}", key);
        }
      });
    }
  }
}
```

### ❌ Cách sai

```java
// ❌ SAI 1: Không config TTL
@Configuration
@EnableCaching
public class CacheConfig {
  @Bean
  public CacheManager cacheManager(RedisConnectionFactory factory) {
    return RedisCacheManager.builder(factory)
      .cacheDefaults(RedisCacheConfiguration.defaultCacheConfig())
      // ❌ Thiếu .entryTtl() → cache tồn tại mãi
      .build();
  }
}

// ❌ SAI 2: TTL = -1 (never expire)
RedisCacheConfiguration config = RedisCacheConfiguration
  .defaultCacheConfig()
  .entryTtl(Duration.ofSeconds(-1)); // ❌ NEVER EXPIRE

// ❌ SAI 3: TTL quá dài cho dynamic data
Map<String, RedisCacheConfiguration> configs = Map.of(
  "userSessions", config.entryTtl(Duration.ofDays(365)) // ❌ 1 năm?!
);

// ❌ SAI 4: TTL quá ngắn cho static data
Map<String, RedisCacheConfiguration> configs = Map.of(
  "countries", config.entryTtl(Duration.ofSeconds(10)) // ❌ 10s → cache thrashing
);

// ❌ SAI 5: Không monitor TTL = -1 keys
// Redis command: KEYS * → nếu thấy key không expire → memory leak

// ❌ SAI 6: Redis maxmemory-policy = noeviction
/*
# redis.conf
maxmemory 1gb
maxmemory-policy noeviction  # ❌ Khi đầy → write fail → app crash
*/
// FIX: dùng allkeys-lru hoặc volatile-lru

// ❌ SAI 7: Cache data lớn với TTL dài
@Cacheable(value = "reports", key = "#reportId")
public byte[] generateLargeReport(Long reportId) {
  // Report 50MB, TTL 1 ngày → 1000 reports = 50GB RAM
  return generateReport(reportId);
}
// FIX: Cache link to S3, không cache binary data
```

### Phát hiện

**Regex patterns:**
```regex
# Config không có entryTtl
@Bean.*CacheManager(?!.*entryTtl).*\{

# TTL = -1 hoặc quá dài
\.entryTtl\(Duration\.of(Days|Hours)\((365|999|[5-9]\d{2})\)

# Cache lớn (byte[], InputStream) không giới hạn TTL
@Cacheable.*\n.*public\s+(byte\[\]|InputStream)

# Redis config thiếu maxmemory-policy
# Cần check redis.conf manually
```

**Checklist:**
```java
// 1. Default TTL được config?
.cacheDefaults(config.entryTtl(Duration.ofMinutes(10))) // ✅

// 2. Custom TTL cho từng cache type?
Map<String, RedisCacheConfiguration> configs = Map.of(
  "static", config.entryTtl(Duration.ofDays(7)),
  "dynamic", config.entryTtl(Duration.ofMinutes(15))
); // ✅

// 3. TTL hợp lý?
// Static (categories, settings): 1 giờ - 7 ngày ✅
// Dynamic (users, sessions): 5-30 phút ✅
// Real-time (prices, status): 10s - 1 phút ✅

// 4. Monitor TTL = -1 keys?
@Scheduled(fixedRate = 60000)
public void checkNoTtlKeys() {
  // Scan keys with TTL = -1
} // ✅

// 5. Redis maxmemory-policy config?
# redis.conf
maxmemory 2gb
maxmemory-policy allkeys-lru # ✅

// 6. Test cache expiration?
@Test
void testCacheExpiration() throws InterruptedException {
  service.getData(1L); // Cache
  Thread.sleep(Duration.ofMinutes(11).toMillis()); // Wait TTL
  service.getData(1L); // Should query DB again
  verify(repo, times(2)).findById(1L); // ✅
}
```

---

## 10.04 - Cache invalidation khi data thay đổi 🔴

### Metadata
- **ID:** `CACHE-004`
- **Mức độ:** 🔴 BẮT BUỘC
- **Lý do:** Stale cache → user thấy data cũ → critical bug, business loss
- **Trade-off:** Invalidation phức tạp → có thể invalidate quá nhiều → cache miss

### Tại sao?

**Vấn đề:**
- Update product price → cache vẫn giữ giá cũ → user mua sai giá
- Delete user → cache vẫn trả user → security issue
- Cascade invalidation: update category → invalidate all products trong category

**Giải pháp:**
- `@CacheEvict`: xóa cache khi update/delete
- `allEntries = true`: xóa toàn bộ cache (dùng khi update ảnh hưởng nhiều entries)
- `beforeInvocation = true`: evict TRƯỚC khi execute method (nếu method throw exception)
- Event-driven invalidation: publish event → listener invalidate cache

### ✅ Cách đúng

```java
// ===== Service: ProductService.java =====
@Service
@Slf4j
public class ProductService {

  @Autowired
  private ProductRepository productRepository;

  @Autowired
  private ApplicationEventPublisher eventPublisher;

  // ===== READ: Cacheable =====
  @Cacheable(value = "products", key = "#id", unless = "#result == null")
  public ProductDto getProduct(Long id) {
    return productRepository.findById(id)
      .map(this::toDto)
      .orElse(null);
  }

  @Cacheable(
    value = "products:category",
    key = "#categoryId + ':' + #page + ':' + #size"
  )
  public Page<ProductDto> getProductsByCategory(Long categoryId, int page, int size) {
    Pageable pageable = PageRequest.of(page, size);
    return productRepository.findByCategoryId(categoryId, pageable)
      .map(this::toDto);
  }

  // ===== UPDATE: Evict single entry =====
  @CacheEvict(value = "products", key = "#id")
  public ProductDto updateProduct(Long id, UpdateProductRequest request) {
    Product product = productRepository.findById(id)
      .orElseThrow(() -> new NotFoundException("Product not found: " + id));

    Long oldCategoryId = product.getCategoryId();

    product.setName(request.name());
    product.setPrice(request.price());
    product.setCategoryId(request.categoryId());

    Product saved = productRepository.save(product);

    // Invalidate category cache nếu category thay đổi
    if (!Objects.equals(oldCategoryId, request.categoryId())) {
      eventPublisher.publishEvent(new CategoryChangedEvent(
        oldCategoryId,
        request.categoryId()
      ));
    }

    log.info("Cache evicted for product: {}", id);
    return toDto(saved);
  }

  // ===== DELETE: Evict + cascade =====
  @CacheEvict(value = "products", key = "#id")
  public void deleteProduct(Long id) {
    Product product = productRepository.findById(id)
      .orElseThrow(() -> new NotFoundException("Product not found: " + id));

    productRepository.delete(product);

    // Cascade invalidation
    eventPublisher.publishEvent(new ProductDeletedEvent(id, product.getCategoryId()));

    log.info("Product deleted and cache evicted: {}", id);
  }

  // ===== CREATE: Evict all (vì list APIs sẽ thay đổi) =====
  @CacheEvict(value = "products:category", allEntries = true)
  public ProductDto createProduct(CreateProductRequest request) {
    Product product = Product.builder()
      .name(request.name())
      .price(request.price())
      .categoryId(request.categoryId())
      .build();

    Product saved = productRepository.save(product);

    log.info("Product created, all category caches evicted");
    return toDto(saved);
  }

  // ===== BULK UPDATE: Multiple evictions =====
  @Caching(evict = {
    @CacheEvict(value = "products", allEntries = true),
    @CacheEvict(value = "products:category", allEntries = true)
  })
  public void bulkUpdatePrices(List<Long> productIds, BigDecimal discountPercent) {
    productRepository.findAllById(productIds).forEach(product -> {
      BigDecimal newPrice = product.getPrice()
        .multiply(BigDecimal.ONE.subtract(discountPercent));
      product.setPrice(newPrice);
    });

    productRepository.flush();
    log.info("Bulk update completed, all caches evicted");
  }

  // ===== Transaction-aware eviction =====
  @Transactional
  @CacheEvict(value = "products", key = "#id")
  public ProductDto updateProductTransactional(Long id, UpdateProductRequest request) {
    // Eviction chỉ trigger SAU KHI transaction commit thành công
    Product product = productRepository.findById(id).orElseThrow();
    product.setName(request.name());
    return toDto(productRepository.save(product));

    // Nếu throw exception → rollback → cache KHÔNG bị evict
  }

  // ===== beforeInvocation: Evict trước khi execute =====
  @CacheEvict(
    value = "products",
    key = "#id",
    beforeInvocation = true // Evict TRƯỚC khi method chạy
  )
  public void updateProductUnsafe(Long id, UpdateProductRequest request) {
    // Nếu method này throw exception → cache đã bị evict
    // Dùng khi không muốn cache inconsistent state
    Product product = productRepository.findById(id).orElseThrow();
    product.setName(request.name());
    productRepository.save(product);
  }
}

// ===== Event: CategoryChangedEvent.java =====
public record CategoryChangedEvent(
  Long oldCategoryId,
  Long newCategoryId
) { }

// ===== Listener: CacheInvalidationListener.java =====
@Component
@Slf4j
public class CacheInvalidationListener {

  @Autowired
  private CacheManager cacheManager;

  @EventListener
  public void onCategoryChanged(CategoryChangedEvent event) {
    // Invalidate cache của cả 2 categories
    evictCategoryCache(event.oldCategoryId());
    evictCategoryCache(event.newCategoryId());
  }

  @EventListener
  public void onProductDeleted(ProductDeletedEvent event) {
    // Invalidate category cache
    evictCategoryCache(event.categoryId());
  }

  private void evictCategoryCache(Long categoryId) {
    Cache cache = cacheManager.getCache("products:category");
    if (cache != null) {
      // Evict all entries có categoryId
      cache.clear(); // Hoặc dùng pattern matching nếu Redis
      log.info("Category cache evicted for categoryId: {}", categoryId);
    }
  }

  // ===== Pattern-based eviction với Redis =====
  @Autowired
  private RedisTemplate<String, Object> redisTemplate;

  public void evictByPattern(String pattern) {
    Set<String> keys = redisTemplate.keys(pattern);
    if (keys != null && !keys.isEmpty()) {
      redisTemplate.delete(keys);
      log.info("Evicted {} keys matching pattern: {}", keys.size(), pattern);
    }
  }

  // Example: evict all products in category
  public void evictProductsByCategory(Long categoryId) {
    evictByPattern("products:category:" + categoryId + ":*");
  }
}

// ===== Manual cache eviction service =====
@Service
public class CacheEvictionService {

  @Autowired
  private CacheManager cacheManager;

  public void evictAllCaches() {
    cacheManager.getCacheNames().forEach(cacheName -> {
      Cache cache = cacheManager.getCache(cacheName);
      if (cache != null) {
        cache.clear();
        log.info("Cache cleared: {}", cacheName);
      }
    });
  }

  public void evictCacheByName(String cacheName) {
    Cache cache = cacheManager.getCache(cacheName);
    if (cache != null) {
      cache.clear();
      log.info("Cache cleared: {}", cacheName);
    }
  }

  public void evictCacheEntry(String cacheName, Object key) {
    Cache cache = cacheManager.getCache(cacheName);
    if (cache != null) {
      cache.evict(key);
      log.info("Cache entry evicted: {}:{}", cacheName, key);
    }
  }
}

// ===== Admin endpoint để manual evict =====
@RestController
@RequestMapping("/api/admin/cache")
public class CacheAdminController {

  @Autowired
  private CacheEvictionService cacheEvictionService;

  @PostMapping("/evict-all")
  @PreAuthorize("hasRole('ADMIN')")
  public ResponseEntity<String> evictAll() {
    cacheEvictionService.evictAllCaches();
    return ResponseEntity.ok("All caches evicted");
  }

  @PostMapping("/evict/{cacheName}")
  @PreAuthorize("hasRole('ADMIN')")
  public ResponseEntity<String> evictCache(@PathVariable String cacheName) {
    cacheEvictionService.evictCacheByName(cacheName);
    return ResponseEntity.ok("Cache evicted: " + cacheName);
  }
}
```

### ❌ Cách sai

```java
// ❌ SAI 1: Update/delete không evict cache
public ProductDto updateProduct(Long id, UpdateProductRequest request) {
  Product product = productRepository.findById(id).orElseThrow();
  product.setName(request.name());
  productRepository.save(product);
  // ❌ Thiếu @CacheEvict → cache vẫn giữ data cũ
  return toDto(product);
}

// ❌ SAI 2: Evict sai key
@CacheEvict(value = "products", key = "#request.id") // ❌ Sai param
public ProductDto updateProduct(Long id, UpdateProductRequest request) {
  // Key cache là #id, nhưng evict dùng #request.id
}

// ❌ SAI 3: Cascade invalidation không đủ
@CacheEvict(value = "products", key = "#id")
public void deleteProduct(Long id) {
  productRepository.deleteById(id);
  // ❌ Thiếu evict "products:category" cache
  // → List products by category vẫn hiển thị product đã xóa
}

// ❌ SAI 4: Transaction rollback nhưng cache đã evict
@Transactional
@CacheEvict(value = "products", key = "#id", beforeInvocation = true)
public void updateProduct(Long id, UpdateProductRequest request) {
  Product product = productRepository.findById(id).orElseThrow();
  product.setName(request.name());
  productRepository.save(product);

  if (someCondition) {
    throw new RuntimeException("Rollback!"); // Transaction rollback
    // ❌ Cache đã bị evict (beforeInvocation = true)
    // → Cache miss → query DB → lấy data cũ → cache lại → OK
    // Nhưng nếu có concurrent request → có thể cache data inconsistent
  }
}

// ❌ SAI 5: Evict không đủ trong bulk update
@CacheEvict(value = "products", key = "#productIds[0]") // ❌ Chỉ evict 1 product
public void bulkUpdatePrices(List<Long> productIds, BigDecimal discount) {
  // Update 100 products nhưng chỉ evict 1
}

// ❌ SAI 6: Không evict related caches
@CacheEvict(value = "products", key = "#id")
public void updateProductCategory(Long id, Long newCategoryId) {
  Product product = productRepository.findById(id).orElseThrow();
  product.setCategoryId(newCategoryId);
  productRepository.save(product);
  // ❌ Thiếu evict:
  // - "products:category:{oldCategoryId}" cache
  // - "products:category:{newCategoryId}" cache
  // - "categories" cache (nếu có product count)
}

// ❌ SAI 7: Race condition trong eviction
public void updateProductConcurrent(Long id, String newName) {
  Product product = productRepository.findById(id).orElseThrow();
  product.setName(newName);
  productRepository.save(product);

  // Manual evict SAU KHI save
  Cache cache = cacheManager.getCache("products");
  cache.evict(id);

  // ❌ Race condition:
  // T1: save() → evict()
  // T2:          getProduct() (cache old data) ← T1 chưa evict xong
  // → T2 cache data cũ
}
// FIX: Dùng @CacheEvict annotation (atomic)
```

### Phát hiện

**Regex patterns:**
```regex
# Update/delete method thiếu @CacheEvict
public.*\b(update|delete|remove)\w+\(.*\)(?!.*@CacheEvict)

# @Cacheable có nhưng không có @CacheEvict tương ứng
@Cacheable.*value\s*=\s*"(\w+)"(?!.*@CacheEvict.*value\s*=\s*"\1")

# beforeInvocation = true trong @Transactional
@Transactional.*\n.*@CacheEvict.*beforeInvocation\s*=\s*true

# Bulk operation evict 1 entry
@CacheEvict.*key.*\[0\].*\n.*public.*bulk
```

**Checklist:**
```java
// 1. Mọi update/delete có @CacheEvict?
@CacheEvict(value = "products", key = "#id") // ✅
public void updateProduct(Long id, ...) { }

// 2. Key eviction khớp với key cache?
@Cacheable(key = "#id") + @CacheEvict(key = "#id") // ✅

// 3. Cascade invalidation đầy đủ?
@Caching(evict = {
  @CacheEvict(value = "products", key = "#id"),
  @CacheEvict(value = "products:category", allEntries = true)
}) // ✅

// 4. beforeInvocation phù hợp?
@CacheEvict(beforeInvocation = false) // Default, evict SAU transaction commit ✅

// 5. Bulk operation evict all?
@CacheEvict(allEntries = true) // ✅
public void bulkUpdate(...) { }

// 6. Event-driven invalidation cho complex scenario?
eventPublisher.publishEvent(new ProductUpdatedEvent(...)); // ✅

// 7. Admin endpoint để manual evict?
@PostMapping("/admin/cache/evict-all") // ✅

// 8. Test cache invalidation?
@Test
void testCacheEviction() {
  service.getProduct(1L); // Cache
  service.updateProduct(1L, request); // Evict
  service.getProduct(1L); // Cache MISS
  verify(repo, times(2)).findById(1L); // ✅ 2 queries
}
```

---

## 10.05 - Tránh cache stampede (singleflight / lock) 🟠

### Metadata
- **ID:** `CACHE-005`
- **Mức độ:** 🟠 KHUYẾN NGHỊ
- **Lý do:** Cache expire → 1000 concurrent requests → 1000 DB queries → DB overload
- **Trade-off:** Lock/singleflight → request đầu tiên chậm hơn, complexity tăng

### Tại sao?

**Vấn đề: Cache stampede (thundering herd)**
- Cache expire tại thời điểm peak traffic
- 1000 requests cùng lúc thấy cache miss
- Tất cả query DB → DB connection pool exhausted → timeout → cascade failure

**Giải pháp:**
1. **Singleflight pattern**: chỉ 1 request query DB, các request khác đợi kết quả
2. **Lock-based**: distributed lock (Redis SETNX) để chặn concurrent queries
3. **Probabilistic early expiration**: refresh cache trước khi expire (XFetch)
4. **Cache warming**: pre-load cache khi app start

### ✅ Cách đúng

```java
// ===== 1. Singleflight Pattern với CompletableFuture =====
@Service
@Slf4j
public class SingleflightCacheService {

  private final Map<String, CompletableFuture<Object>> inflightRequests =
    new ConcurrentHashMap<>();

  @Autowired
  private RedisTemplate<String, Object> redisTemplate;

  @Autowired
  private ProductRepository productRepository;

  public ProductDto getProduct(Long productId) {
    String cacheKey = "product:" + productId;

    // 1. Check cache
    ProductDto cached = (ProductDto) redisTemplate.opsForValue().get(cacheKey);
    if (cached != null) {
      return cached;
    }

    // 2. Singleflight: chỉ 1 request query DB
    CompletableFuture<Object> future = inflightRequests.computeIfAbsent(
      cacheKey,
      key -> CompletableFuture.supplyAsync(() -> {
        log.info("Cache MISS, querying DB for: {}", productId);

        ProductDto product = productRepository.findById(productId)
          .map(this::toDto)
          .orElse(null);

        if (product != null) {
          redisTemplate.opsForValue().set(cacheKey, product, Duration.ofHours(1));
        }

        return product;
      }).whenComplete((result, ex) -> {
        // Remove từ inflight sau khi hoàn thành
        inflightRequests.remove(cacheKey);
      })
    );

    try {
      return (ProductDto) future.get(5, TimeUnit.SECONDS);
    } catch (Exception e) {
      log.error("Error getting product from singleflight", e);
      inflightRequests.remove(cacheKey);
      throw new RuntimeException("Failed to get product", e);
    }
  }

  private ProductDto toDto(Product product) {
    return ProductDto.builder()
      .id(product.getId())
      .name(product.getName())
      .build();
  }
}

// ===== 2. Distributed Lock với Redisson =====
@Service
@Slf4j
public class DistributedLockCacheService {

  @Autowired
  private RedissonClient redissonClient;

  @Autowired
  private RedisTemplate<String, Object> redisTemplate;

  @Autowired
  private ProductRepository productRepository;

  public ProductDto getProduct(Long productId) {
    String cacheKey = "product:" + productId;

    // 1. Check cache
    ProductDto cached = (ProductDto) redisTemplate.opsForValue().get(cacheKey);
    if (cached != null) {
      return cached;
    }

    // 2. Acquire distributed lock
    String lockKey = "lock:product:" + productId;
    RLock lock = redissonClient.getLock(lockKey);

    try {
      // Wait max 5s để acquire lock, lock tự release sau 10s
      boolean acquired = lock.tryLock(5, 10, TimeUnit.SECONDS);

      if (!acquired) {
        log.warn("Failed to acquire lock for: {}", productId);
        throw new RuntimeException("Too many concurrent requests");
      }

      // Double-check cache (có thể thread khác đã load)
      cached = (ProductDto) redisTemplate.opsForValue().get(cacheKey);
      if (cached != null) {
        return cached;
      }

      // Query DB
      log.info("Lock acquired, querying DB for: {}", productId);
      ProductDto product = productRepository.findById(productId)
        .map(this::toDto)
        .orElse(null);

      if (product != null) {
        redisTemplate.opsForValue().set(cacheKey, product, Duration.ofHours(1));
      }

      return product;

    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      throw new RuntimeException("Lock interrupted", e);
    } finally {
      if (lock.isHeldByCurrentThread()) {
        lock.unlock();
      }
    }
  }

  private ProductDto toDto(Product product) {
    return ProductDto.builder()
      .id(product.getId())
      .name(product.getName())
      .build();
  }
}

// ===== 3. Probabilistic Early Expiration (XFetch) =====
@Service
@Slf4j
public class XFetchCacheService {

  @Autowired
  private RedisTemplate<String, Object> redisTemplate;

  @Autowired
  private ProductRepository productRepository;

  private static final double BETA = 1.0; // Tuning parameter

  public ProductDto getProduct(Long productId) {
    String cacheKey = "product:" + productId;
    long now = System.currentTimeMillis();

    // Get cache với timestamp
    CachedValue<ProductDto> cached = (CachedValue<ProductDto>)
      redisTemplate.opsForValue().get(cacheKey);

    if (cached != null) {
      long delta = now - cached.cachedAt();
      long ttl = cached.ttl();

      // XFetch formula: random() < delta * BETA / TTL
      double probability = (double) delta * BETA / ttl;

      if (Math.random() < probability) {
        log.info("Probabilistic early refresh for: {}", productId);
        return refreshCache(productId, cacheKey);
      }

      return cached.value();
    }

    // Cache miss
    return refreshCache(productId, cacheKey);
  }

  private ProductDto refreshCache(Long productId, String cacheKey) {
    ProductDto product = productRepository.findById(productId)
      .map(this::toDto)
      .orElse(null);

    if (product != null) {
      long ttl = Duration.ofHours(1).toMillis();
      CachedValue<ProductDto> cachedValue = new CachedValue<>(
        product,
        System.currentTimeMillis(),
        ttl
      );
      redisTemplate.opsForValue().set(cacheKey, cachedValue, Duration.ofMillis(ttl));
    }

    return product;
  }

  private ProductDto toDto(Product product) {
    return ProductDto.builder()
      .id(product.getId())
      .name(product.getName())
      .build();
  }

  @Builder
  private record CachedValue<T>(
    T value,
    long cachedAt,
    long ttl
  ) implements Serializable { }
}

// ===== 4. Cache Warming on Startup =====
@Component
@Slf4j
public class CacheWarmer {

  @Autowired
  private ProductRepository productRepository;

  @Autowired
  private RedisTemplate<String, Object> redisTemplate;

  @EventListener(ApplicationReadyEvent.class)
  public void warmCache() {
    log.info("Starting cache warming...");

    // Load top 100 popular products
    List<Product> popularProducts = productRepository
      .findTop100ByOrderByViewCountDesc();

    popularProducts.forEach(product -> {
      String cacheKey = "product:" + product.getId();
      ProductDto dto = toDto(product);
      redisTemplate.opsForValue().set(cacheKey, dto, Duration.ofHours(1));
    });

    log.info("Cache warmed with {} products", popularProducts.size());
  }

  private ProductDto toDto(Product product) {
    return ProductDto.builder()
      .id(product.getId())
      .name(product.getName())
      .build();
  }
}

// ===== 5. Scheduled Cache Refresh (Background job) =====
@Component
@Slf4j
public class CacheRefreshScheduler {

  @Autowired
  private ProductRepository productRepository;

  @Autowired
  private RedisTemplate<String, Object> redisTemplate;

  @Scheduled(fixedRate = 30, timeUnit = TimeUnit.MINUTES) // Refresh mỗi 30 phút
  public void refreshPopularProductsCache() {
    log.info("Refreshing popular products cache...");

    List<Product> products = productRepository.findTop100ByOrderByViewCountDesc();

    products.forEach(product -> {
      String cacheKey = "product:" + product.getId();
      ProductDto dto = toDto(product);
      redisTemplate.opsForValue().set(cacheKey, dto, Duration.ofHours(1));
    });

    log.info("Refreshed {} products in cache", products.size());
  }

  private ProductDto toDto(Product product) {
    return ProductDto.builder()
      .id(product.getId())
      .name(product.getName())
      .build();
  }
}

// ===== Dependencies: pom.xml =====
/*
<dependency>
  <groupId>org.redisson</groupId>
  <artifactId>redisson-spring-boot-starter</artifactId>
  <version>3.25.2</version>
</dependency>
*/

// ===== Config: RedissonConfig.java =====
@Configuration
public class RedissonConfig {

  @Bean
  public RedissonClient redissonClient() {
    Config config = new Config();
    config.useSingleServer()
      .setAddress("redis://localhost:6379")
      .setConnectionPoolSize(50)
      .setConnectionMinimumIdleSize(10);

    return Redisson.create(config);
  }
}
```

### ❌ Cách sai

```java
// ❌ SAI 1: Không xử lý cache stampede
@Cacheable(value = "products", key = "#id")
public ProductDto getProduct(Long id) {
  // 1000 concurrent requests → 1000 DB queries khi cache expire
  return productRepository.findById(id).map(this::toDto).orElse(null);
}

// ❌ SAI 2: Lock local (không distributed)
private final Map<Long, Object> locks = new ConcurrentHashMap<>();

public ProductDto getProduct(Long id) {
  synchronized (locks.computeIfAbsent(id, k -> new Object())) {
    // ❌ Lock chỉ work trên 1 JVM
    // Multi-instance app → mỗi instance vẫn query DB
  }
}

// ❌ SAI 3: Lock timeout quá dài
RLock lock = redissonClient.getLock(lockKey);
lock.lock(60, TimeUnit.SECONDS); // ❌ 60s quá dài
// Nếu thread crash → lock stuck 60s → all requests fail

// ❌ SAI 4: Không double-check cache sau khi acquire lock
if (lock.tryLock()) {
  ProductDto product = queryDatabase(id); // ❌ Query trực tiếp
  cache.put(id, product);
  // Nếu 2 threads acquire lock tuần tự → query DB 2 lần
}
// FIX: Double-check cache trước khi query

// ❌ SAI 5: Cache warming block app startup
@EventListener(ApplicationReadyEvent.class)
public void warmCache() {
  List<Product> products = productRepository.findAll(); // ❌ Load 1M records
  // App startup bị block 10 phút
}
// FIX: Chỉ load top N, hoặc async

// ❌ SAI 6: Singleflight không cleanup
private final Map<String, CompletableFuture<Object>> inflight = new ConcurrentHashMap<>();

public Object get(String key) {
  CompletableFuture<Object> future = inflight.computeIfAbsent(key, k ->
    CompletableFuture.supplyAsync(() -> queryDB(key))
    // ❌ Không remove khỏi map sau khi done → memory leak
  );
}

// ❌ SAI 7: XFetch với BETA không phù hợp
private static final double BETA = 10.0; // ❌ Quá lớn
// → Refresh quá sớm → cache hit rate thấp → DB overload
```

### Phát hiện

**Regex patterns:**
```regex
# @Cacheable không có lock/singleflight
@Cacheable(?!.*synchronized)(?!.*Lock)(?!.*tryLock)

# Lock local (synchronized) trong cache logic
synchronized.*\n.*cache

# Lock timeout > 30s
tryLock\(\d+,\s*(60|[1-9]\d{2,})

# Cache warming trong @PostConstruct/ApplicationReadyEvent
@(PostConstruct|EventListener).*\n.*public.*warmCache.*\n.*findAll\(\)
```

**Checklist:**
```java
// 1. High-traffic cache có singleflight/lock?
CompletableFuture<Object> future = inflightRequests.computeIfAbsent(...); // ✅

// 2. Distributed lock (không phải local)?
RLock lock = redissonClient.getLock(lockKey); // ✅

// 3. Lock timeout hợp lý (< 10s)?
lock.tryLock(5, 10, TimeUnit.SECONDS); // ✅

// 4. Double-check cache sau acquire lock?
if (lock.tryLock()) {
  cached = redisTemplate.get(key); // Double-check
  if (cached != null) return cached;
  // Query DB
} // ✅

// 5. Cleanup inflight requests?
future.whenComplete((result, ex) -> inflightRequests.remove(key)); // ✅

// 6. Cache warming async + limit records?
@Async
public void warmCache() {
  List<Product> top100 = repo.findTop100(); // ✅
}

// 7. XFetch BETA tuning (0.5 - 2.0)?
private static final double BETA = 1.0; // ✅

// 8. Load test để verify?
// JMeter: 1000 concurrent requests khi cache expire
// → Chỉ 1 DB query (singleflight work) ✅
```

---

## 10.06 - Serialization format phù hợp (JSON vs Kryo vs Protobuf) 🟡

### Metadata
- **ID:** `CACHE-006`
- **Mức độ:** 🟡 NÊN CÓ
- **Lý do:** Serialization tối ưu → giảm 50-70% memory + network bandwidth
- **Trade-off:** Binary format (Kryo, Protobuf) → không human-readable, compatibility risk

### Tại sao?

**Vấn đề:**
- JSON: human-readable nhưng verbose (field names, whitespace)
- Example: `{"id":1,"name":"Product"}` vs binary `\x01\x07Product`
- 10K cache entries × 1KB JSON = 10MB vs 3MB binary → 70% saving

**Lựa chọn serialization:**
1. **JSON (Jackson)**: Default, human-readable, debug dễ, tương thích tốt
2. **Kryo**: Binary, nhanh (2-10x), nhỏ (50-70%), nhưng không version-safe
3. **Protobuf**: Binary, compact, version-safe, nhưng cần schema (.proto file)
4. **FST**: Fast alternative to Java Serialization

**Khuyến nghị:**
- Dev/staging: JSON (debug dễ)
- Production: Kryo (performance) hoặc Protobuf (compatibility)

### ✅ Cách đúng

```java
// ===== 1. JSON Serialization (Default) =====
@Configuration
public class JsonCacheConfig {

  @Bean
  public RedisCacheManager cacheManager(RedisConnectionFactory factory) {
    RedisCacheConfiguration config = RedisCacheConfiguration
      .defaultCacheConfig()
      .entryTtl(Duration.ofHours(1))
      .serializeKeysWith(RedisSerializationContext.SerializationPair
        .fromSerializer(new StringRedisSerializer()))
      .serializeValuesWith(RedisSerializationContext.SerializationPair
        .fromSerializer(new GenericJackson2JsonRedisSerializer()))
      .disableCachingNullValues();

    return RedisCacheManager.builder(factory)
      .cacheDefaults(config)
      .build();
  }
}

// ===== 2. Kryo Serialization (Fast + Compact) =====
@Configuration
public class KryoCacheConfig {

  @Bean
  public RedisCacheManager cacheManager(RedisConnectionFactory factory) {
    RedisCacheConfiguration config = RedisCacheConfiguration
      .defaultCacheConfig()
      .entryTtl(Duration.ofHours(1))
      .serializeKeysWith(RedisSerializationContext.SerializationPair
        .fromSerializer(new StringRedisSerializer()))
      .serializeValuesWith(RedisSerializationContext.SerializationPair
        .fromSerializer(new KryoRedisSerializer<>()))
      .disableCachingNullValues();

    return RedisCacheManager.builder(factory)
      .cacheDefaults(config)
      .build();
  }

  // Custom Kryo Serializer
  public static class KryoRedisSerializer<T> implements RedisSerializer<T> {

    private final ThreadLocal<Kryo> kryoThreadLocal = ThreadLocal.withInitial(() -> {
      Kryo kryo = new Kryo();
      kryo.setRegistrationRequired(false); // Auto-register classes
      kryo.setReferences(true); // Support circular references

      // Register common classes để tối ưu
      kryo.register(ArrayList.class);
      kryo.register(HashMap.class);
      kryo.register(HashSet.class);

      return kryo;
    });

    @Override
    public byte[] serialize(T value) throws SerializationException {
      if (value == null) {
        return null;
      }

      try (ByteArrayOutputStream baos = new ByteArrayOutputStream();
           Output output = new Output(baos)) {

        kryoThreadLocal.get().writeClassAndObject(output, value);
        output.flush();
        return baos.toByteArray();

      } catch (Exception e) {
        throw new SerializationException("Failed to serialize with Kryo", e);
      }
    }

    @Override
    @SuppressWarnings("unchecked")
    public T deserialize(byte[] bytes) throws SerializationException {
      if (bytes == null || bytes.length == 0) {
        return null;
      }

      try (Input input = new Input(new ByteArrayInputStream(bytes))) {
        return (T) kryoThreadLocal.get().readClassAndObject(input);
      } catch (Exception e) {
        throw new SerializationException("Failed to deserialize with Kryo", e);
      }
    }
  }
}

// ===== 3. Protobuf Serialization (Version-safe) =====
// File: product.proto
/*
syntax = "proto3";

package com.example.cache;

message ProductProto {
  int64 id = 1;
  string name = 2;
  double price = 3;
  string category = 4;
}
*/

@Configuration
public class ProtobufCacheConfig {

  @Bean
  public RedisCacheManager cacheManager(RedisConnectionFactory factory) {
    RedisCacheConfiguration config = RedisCacheConfiguration
      .defaultCacheConfig()
      .entryTtl(Duration.ofHours(1))
      .serializeKeysWith(RedisSerializationContext.SerializationPair
        .fromSerializer(new StringRedisSerializer()))
      .serializeValuesWith(RedisSerializationContext.SerializationPair
        .fromSerializer(new ProtobufRedisSerializer()))
      .disableCachingNullValues();

    return RedisCacheManager.builder(factory)
      .cacheDefaults(config)
      .build();
  }

  public static class ProtobufRedisSerializer implements RedisSerializer<Message> {

    @Override
    public byte[] serialize(Message message) throws SerializationException {
      if (message == null) {
        return null;
      }
      return message.toByteArray();
    }

    @Override
    public Message deserialize(byte[] bytes) throws SerializationException {
      if (bytes == null || bytes.length == 0) {
        return null;
      }

      try {
        // Cần biết message type để parse
        // Workaround: lưu type name trong header hoặc dùng Any
        return ProductProto.parseFrom(bytes);
      } catch (InvalidProtocolBufferException e) {
        throw new SerializationException("Failed to deserialize protobuf", e);
      }
    }
  }
}

// ===== 4. Hybrid: JSON cho dev, Kryo cho prod =====
@Configuration
public class HybridCacheConfig {

  @Value("${spring.profiles.active:dev}")
  private String activeProfile;

  @Bean
  public RedisCacheManager cacheManager(RedisConnectionFactory factory) {
    RedisSerializer<?> valueSerializer = "prod".equals(activeProfile)
      ? new KryoRedisSerializer<>()
      : new GenericJackson2JsonRedisSerializer();

    RedisCacheConfiguration config = RedisCacheConfiguration
      .defaultCacheConfig()
      .entryTtl(Duration.ofHours(1))
      .serializeKeysWith(RedisSerializationContext.SerializationPair
        .fromSerializer(new StringRedisSerializer()))
      .serializeValuesWith(RedisSerializationContext.SerializationPair
        .fromSerializer(valueSerializer))
      .disableCachingNullValues();

    return RedisCacheManager.builder(factory)
      .cacheDefaults(config)
      .build();
  }
}

// ===== 5. Compression cho large objects =====
public static class CompressedRedisSerializer<T> implements RedisSerializer<T> {

  private final RedisSerializer<T> delegate;

  public CompressedRedisSerializer(RedisSerializer<T> delegate) {
    this.delegate = delegate;
  }

  @Override
  public byte[] serialize(T value) throws SerializationException {
    byte[] serialized = delegate.serialize(value);
    if (serialized == null || serialized.length < 1024) {
      return serialized; // Không compress nếu < 1KB
    }

    try (ByteArrayOutputStream baos = new ByteArrayOutputStream();
         GZIPOutputStream gzip = new GZIPOutputStream(baos)) {

      gzip.write(serialized);
      gzip.finish();
      return baos.toByteArray();

    } catch (IOException e) {
      throw new SerializationException("Compression failed", e);
    }
  }

  @Override
  public T deserialize(byte[] bytes) throws SerializationException {
    if (bytes == null || bytes.length == 0) {
      return null;
    }

    try {
      // Detect GZIP magic number (1f 8b)
      if (bytes.length > 2 && bytes[0] == (byte) 0x1f && bytes[1] == (byte) 0x8b) {
        try (ByteArrayInputStream bais = new ByteArrayInputStream(bytes);
             GZIPInputStream gzip = new GZIPInputStream(bais);
             ByteArrayOutputStream baos = new ByteArrayOutputStream()) {

          byte[] buffer = new byte[4096];
          int len;
          while ((len = gzip.read(buffer)) > 0) {
            baos.write(buffer, 0, len);
          }
          bytes = baos.toByteArray();
        }
      }

      return delegate.deserialize(bytes);

    } catch (IOException e) {
      throw new SerializationException("Decompression failed", e);
    }
  }
}

// Usage
@Bean
public RedisCacheManager cacheManager(RedisConnectionFactory factory) {
  RedisSerializer<?> valueSerializer = new CompressedRedisSerializer<>(
    new GenericJackson2JsonRedisSerializer()
  );

  RedisCacheConfiguration config = RedisCacheConfiguration
    .defaultCacheConfig()
    .serializeValuesWith(RedisSerializationContext.SerializationPair
      .fromSerializer(valueSerializer));

  return RedisCacheManager.builder(factory)
    .cacheDefaults(config)
    .build();
}

// ===== 6. Benchmark serialization performance =====
@Component
public class SerializationBenchmark {

  @Test
  public void benchmarkSerializers() {
    ProductDto product = ProductDto.builder()
      .id(1L)
      .name("Test Product")
      .price(BigDecimal.valueOf(99.99))
      .build();

    List<RedisSerializer<ProductDto>> serializers = List.of(
      new GenericJackson2JsonRedisSerializer(),
      new KryoRedisSerializer<>()
    );

    serializers.forEach(serializer -> {
      long start = System.nanoTime();

      for (int i = 0; i < 10000; i++) {
        byte[] serialized = serializer.serialize(product);
        ProductDto deserialized = (ProductDto) serializer.deserialize(serialized);
      }

      long duration = System.nanoTime() - start;
      byte[] sample = serializer.serialize(product);

      System.out.printf("%s: %dms, size: %d bytes%n",
        serializer.getClass().getSimpleName(),
        duration / 1_000_000,
        sample.length
      );
    });
  }
}

// ===== Dependencies: pom.xml =====
/*
<!-- Kryo -->
<dependency>
  <groupId>com.esotericsoftware</groupId>
  <artifactId>kryo</artifactId>
  <version>5.5.0</version>
</dependency>

<!-- Protobuf -->
<dependency>
  <groupId>com.google.protobuf</groupId>
  <artifactId>protobuf-java</artifactId>
  <version>3.25.1</version>
</dependency>

<!-- FST -->
<dependency>
  <groupId>de.ruedigermoeller</groupId>
  <artifactId>fst</artifactId>
  <version>3.0.4</version>
</dependency>
*/
```

### ❌ Cách sai

```java
// ❌ SAI 1: Dùng Java default serialization
config.serializeValuesWith(RedisSerializationContext.SerializationPair
  .fromSerializer(new JdkSerializationRedisSerializer())
);
// ❌ Chậm (10x so với Kryo), lớn (2-3x so với JSON), security risk

// ❌ SAI 2: Kryo không config references
Kryo kryo = new Kryo();
kryo.setReferences(false); // ❌ Circular reference → StackOverflowError

// ❌ SAI 3: Protobuf deserialize sai type
public Message deserialize(byte[] bytes) {
  return ProductProto.parseFrom(bytes); // ❌ Hardcode type
  // Nếu cache chứa UserProto → parse fail
}
// FIX: Lưu type info trong metadata hoặc dùng separate cache per type

// ❌ SAI 4: Compress mọi object (kể cả nhỏ)
public byte[] serialize(Object value) {
  byte[] serialized = delegate.serialize(value);
  return compress(serialized); // ❌ Compress 10 bytes → lãng phí CPU
}
// FIX: Chỉ compress nếu > 1KB

// ❌ SAI 5: JSON với circular reference
@JsonBackReference // ❌ Quên annotate
public class Product {
  private Category category;
}

public class Category {
  private List<Product> products; // Circular ref → serialize fail
}

// ❌ SAI 6: Kryo thread-unsafe
private final Kryo kryo = new Kryo(); // ❌ Shared instance

public byte[] serialize(Object value) {
  // Thread 1 và Thread 2 cùng dùng kryo → race condition
  return kryo.writeObjectOrNull(new Output(), value).toBytes();
}
// FIX: Dùng ThreadLocal<Kryo>

// ❌ SAI 7: Không benchmark trước khi production
// Chọn Kryo vì "nghe nói nhanh" → không test với real data
// → Production: Kryo slower than JSON (vì data structure phức tạp)
```

### Phát hiện

**Regex patterns:**
```regex
# Dùng JdkSerializationRedisSerializer
JdkSerializationRedisSerializer

# Kryo không dùng ThreadLocal
private.*Kryo\s+kryo(?!.*ThreadLocal)

# Compression không check size
compress\(serialized\)(?!.*length|size)

# Protobuf deserialize hardcode type
parseFrom\(bytes\)(?!.*switch|instanceof)
```

**Checklist:**
```java
// 1. KHÔNG dùng JdkSerializationRedisSerializer?
// ❌ JdkSerializationRedisSerializer
// ✅ GenericJackson2JsonRedisSerializer hoặc Kryo

// 2. Kryo dùng ThreadLocal?
ThreadLocal<Kryo> kryoThreadLocal = ThreadLocal.withInitial(...); // ✅

// 3. Compression chỉ cho large objects?
if (serialized.length > 1024) compress(...); // ✅

// 4. Profile-based serializer (JSON dev, Kryo prod)?
String profile = env.getActiveProfiles()[0];
RedisSerializer<?> serializer = "prod".equals(profile)
  ? new KryoRedisSerializer()
  : new GenericJackson2JsonRedisSerializer(); // ✅

// 5. Benchmark với real data?
@Test
void benchmarkSerializers() {
  // Test với 1000 ProductDto
  // Measure: serialize time, size, deserialize time
} // ✅

// 6. Circular reference handled?
@JsonManagedReference / @JsonBackReference // ✅
// hoặc kryo.setReferences(true)

// 7. Monitor serialization errors?
@ExceptionHandler(SerializationException.class)
public ResponseEntity<?> handleSerializationError(SerializationException e) {
  log.error("Serialization failed", e);
  return ResponseEntity.status(500).body("Cache error");
} // ✅
```

---

## 10.07 - Cache metrics (hit rate, miss rate, eviction) 🟡

### Metadata
- **ID:** `CACHE-007`
- **Mức độ:** 🟡 NÊN CÓ
- **Lý do:** Monitoring → phát hiện cache ineffective, tune TTL, detect issues
- **Trade-off:** Metrics overhead (1-2% performance), storage cost

### Tại sao?

**Vấn đề:**
- Cache hit rate thấp (< 70%) → TTL quá ngắn hoặc key strategy sai
- Eviction rate cao → memory không đủ → cần tăng maxmemory
- Latency tăng đột ngột → cache stampede hoặc Redis down

**Metrics cần track:**
1. **Hit rate**: hits / (hits + misses) → should be > 80%
2. **Miss rate**: 1 - hit rate
3. **Eviction rate**: entries evicted per second → should be ~0
4. **Latency**: cache GET/SET time → should be < 5ms
5. **Memory usage**: used memory / maxmemory → should be < 80%
6. **Key count**: total keys per cache

### ✅ Cách đúng

```java
// ===== 1. Micrometer Metrics với Spring Boot Actuator =====
@Configuration
public class CacheMetricsConfig {

  @Bean
  public CacheManager cacheManager(
    RedisConnectionFactory factory,
    MeterRegistry meterRegistry
  ) {
    RedisCacheConfiguration config = RedisCacheConfiguration
      .defaultCacheConfig()
      .entryTtl(Duration.ofHours(1));

    RedisCacheManager cacheManager = RedisCacheManager.builder(factory)
      .cacheDefaults(config)
      .build();

    // Enable cache metrics
    CacheMetricsRegistrar.register(
      cacheManager,
      meterRegistry,
      "spring.cache" // Metric prefix
    );

    return cacheManager;
  }
}

// application.yml
/*
management:
  endpoints:
    web:
      exposure:
        include: health,metrics,prometheus
  metrics:
    export:
      prometheus:
        enabled: true
    tags:
      application: myapp
      environment: production
*/

// ===== 2. Custom Cache Statistics =====
@Component
@Slf4j
public class CacheStatistics {

  private final AtomicLong hits = new AtomicLong(0);
  private final AtomicLong misses = new AtomicLong(0);
  private final AtomicLong puts = new AtomicLong(0);
  private final AtomicLong evictions = new AtomicLong(0);

  @Autowired
  private MeterRegistry meterRegistry;

  @PostConstruct
  public void init() {
    // Register Gauges
    Gauge.builder("cache.hit.rate", this, CacheStatistics::getHitRate)
      .description("Cache hit rate")
      .register(meterRegistry);

    Gauge.builder("cache.miss.rate", this, CacheStatistics::getMissRate)
      .description("Cache miss rate")
      .register(meterRegistry);

    // Register Counters
    meterRegistry.counter("cache.hits", "result", "hit");
    meterRegistry.counter("cache.misses", "result", "miss");
    meterRegistry.counter("cache.puts", "operation", "put");
    meterRegistry.counter("cache.evictions", "operation", "evict");
  }

  public void recordHit() {
    hits.incrementAndGet();
    meterRegistry.counter("cache.hits").increment();
  }

  public void recordMiss() {
    misses.incrementAndGet();
    meterRegistry.counter("cache.misses").increment();
  }

  public void recordPut() {
    puts.incrementAndGet();
    meterRegistry.counter("cache.puts").increment();
  }

  public void recordEviction() {
    evictions.incrementAndGet();
    meterRegistry.counter("cache.evictions").increment();
  }

  public double getHitRate() {
    long totalRequests = hits.get() + misses.get();
    return totalRequests == 0 ? 0.0 : (double) hits.get() / totalRequests;
  }

  public double getMissRate() {
    return 1.0 - getHitRate();
  }

  @Scheduled(fixedRate = 60000) // Log mỗi phút
  public void logStatistics() {
    log.info("Cache Statistics - Hit Rate: {:.2f}%, Misses: {}, Evictions: {}",
      getHitRate() * 100,
      misses.get(),
      evictions.get()
    );
  }

  public void reset() {
    hits.set(0);
    misses.set(0);
    puts.set(0);
    evictions.set(0);
  }
}

// ===== 3. Cache Aspect để track metrics =====
@Aspect
@Component
@Slf4j
public class CacheMetricsAspect {

  @Autowired
  private CacheStatistics statistics;

  @Autowired
  private MeterRegistry meterRegistry;

  @Around("@annotation(cacheable)")
  public Object aroundCacheable(ProceedingJoinPoint pjp, Cacheable cacheable) throws Throwable {
    String cacheName = cacheable.value()[0];
    Timer.Sample sample = Timer.start(meterRegistry);

    try {
      Object result = pjp.proceed();

      if (result != null) {
        statistics.recordHit();
        sample.stop(Timer.builder("cache.get.time")
          .tag("cache", cacheName)
          .tag("result", "hit")
          .register(meterRegistry));
      } else {
        statistics.recordMiss();
        sample.stop(Timer.builder("cache.get.time")
          .tag("cache", cacheName)
          .tag("result", "miss")
          .register(meterRegistry));
      }

      return result;

    } catch (Exception e) {
      sample.stop(Timer.builder("cache.get.time")
        .tag("cache", cacheName)
        .tag("result", "error")
        .register(meterRegistry));
      throw e;
    }
  }

  @AfterReturning("@annotation(cacheEvict)")
  public void afterCacheEvict(CacheEvict cacheEvict) {
    statistics.recordEviction();
    meterRegistry.counter("cache.evict.count", "cache", cacheEvict.value()[0])
      .increment();
  }

  @AfterReturning("@annotation(cachePut)")
  public void afterCachePut(CachePut cachePut) {
    statistics.recordPut();
    meterRegistry.counter("cache.put.count", "cache", cachePut.value()[0])
      .increment();
  }
}

// ===== 4. Redis Metrics với RedisTemplate =====
@Component
@Slf4j
public class RedisMetrics {

  @Autowired
  private RedisTemplate<String, Object> redisTemplate;

  @Autowired
  private MeterRegistry meterRegistry;

  @Scheduled(fixedRate = 30000) // Collect mỗi 30s
  public void collectRedisMetrics() {
    RedisConnection connection = null;
    try {
      connection = redisTemplate.getConnectionFactory().getConnection();
      Properties info = connection.info();

      // Memory usage
      long usedMemory = Long.parseLong(info.getProperty("used_memory", "0"));
      long maxMemory = Long.parseLong(info.getProperty("maxmemory", "0"));

      Gauge.builder("redis.memory.used", () -> usedMemory)
        .description("Redis used memory in bytes")
        .register(meterRegistry);

      Gauge.builder("redis.memory.max", () -> maxMemory)
        .description("Redis max memory in bytes")
        .register(meterRegistry);

      // Hit rate (từ Redis INFO stats)
      long keyspaceHits = Long.parseLong(info.getProperty("keyspace_hits", "0"));
      long keyspaceMisses = Long.parseLong(info.getProperty("keyspace_misses", "0"));
      long totalRequests = keyspaceHits + keyspaceMisses;

      double redisHitRate = totalRequests == 0 ? 0.0 : (double) keyspaceHits / totalRequests;

      Gauge.builder("redis.hit.rate", () -> redisHitRate)
        .description("Redis keyspace hit rate")
        .register(meterRegistry);

      // Connected clients
      long connectedClients = Long.parseLong(info.getProperty("connected_clients", "0"));

      Gauge.builder("redis.clients.connected", () -> connectedClients)
        .description("Number of connected Redis clients")
        .register(meterRegistry);

      // Evicted keys
      long evictedKeys = Long.parseLong(info.getProperty("evicted_keys", "0"));

      meterRegistry.counter("redis.evicted.keys", "total", String.valueOf(evictedKeys));

      log.debug("Redis Metrics - Hit Rate: {:.2f}%, Memory: {}MB / {}MB",
        redisHitRate * 100,
        usedMemory / 1024 / 1024,
        maxMemory / 1024 / 1024
      );

    } catch (Exception e) {
      log.error("Failed to collect Redis metrics", e);
    } finally {
      if (connection != null) {
        connection.close();
      }
    }
  }

  public Map<String, Object> getRedisInfo() {
    RedisConnection connection = null;
    try {
      connection = redisTemplate.getConnectionFactory().getConnection();
      Properties info = connection.info();

      return Map.of(
        "usedMemory", info.getProperty("used_memory"),
        "maxMemory", info.getProperty("maxmemory"),
        "hitRate", calculateHitRate(info),
        "connectedClients", info.getProperty("connected_clients"),
        "evictedKeys", info.getProperty("evicted_keys")
      );

    } finally {
      if (connection != null) {
        connection.close();
      }
    }
  }

  private double calculateHitRate(Properties info) {
    long hits = Long.parseLong(info.getProperty("keyspace_hits", "0"));
    long misses = Long.parseLong(info.getProperty("keyspace_misses", "0"));
    long total = hits + misses;
    return total == 0 ? 0.0 : (double) hits / total;
  }
}

// ===== 5. Grafana Dashboard Queries (PromQL) =====
/*
# Cache Hit Rate
rate(cache_hits_total[5m]) / (rate(cache_hits_total[5m]) + rate(cache_misses_total[5m]))

# Cache Miss Rate
rate(cache_misses_total[5m]) / (rate(cache_hits_total[5m]) + rate(cache_misses_total[5m]))

# Cache GET Latency (p95)
histogram_quantile(0.95, rate(cache_get_time_bucket[5m]))

# Redis Memory Usage
redis_memory_used / redis_memory_max * 100

# Eviction Rate
rate(redis_evicted_keys[5m])

# Keys per Cache
redis_db_keys{db="0"}
*/

// ===== 6. Alert Rules (Prometheus) =====
/*
groups:
  - name: cache_alerts
    rules:
      - alert: CacheHitRateLow
        expr: cache_hit_rate < 0.7
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Cache hit rate below 70%"
          description: "Cache {{ $labels.cache }} hit rate is {{ $value }}"

      - alert: RedisMemoryHigh
        expr: redis_memory_used / redis_memory_max > 0.9
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "Redis memory usage > 90%"

      - alert: CacheEvictionHigh
        expr: rate(redis_evicted_keys[5m]) > 100
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High cache eviction rate"
*/

// ===== 7. Health Check với Cache =====
@Component
public class CacheHealthIndicator implements HealthIndicator {

  @Autowired
  private RedisTemplate<String, Object> redisTemplate;

  @Autowired
  private CacheStatistics statistics;

  @Override
  public Health health() {
    try {
      redisTemplate.getConnectionFactory().getConnection().ping();

      double hitRate = statistics.getHitRate();

      if (hitRate < 0.5) {
        return Health.down()
          .withDetail("hitRate", hitRate)
          .withDetail("status", "Hit rate too low")
          .build();
      }

      return Health.up()
        .withDetail("hitRate", hitRate)
        .withDetail("hits", statistics.hits.get())
        .withDetail("misses", statistics.misses.get())
        .build();

    } catch (Exception e) {
      return Health.down()
        .withException(e)
        .build();
    }
  }
}

// ===== 8. Admin Endpoint để view metrics =====
@RestController
@RequestMapping("/api/admin/cache/metrics")
public class CacheMetricsController {

  @Autowired
  private CacheStatistics statistics;

  @Autowired
  private RedisMetrics redisMetrics;

  @GetMapping
  public ResponseEntity<Map<String, Object>> getMetrics() {
    Map<String, Object> metrics = Map.of(
      "application", Map.of(
        "hitRate", statistics.getHitRate(),
        "missRate", statistics.getMissRate(),
        "hits", statistics.hits.get(),
        "misses", statistics.misses.get(),
        "evictions", statistics.evictions.get()
      ),
      "redis", redisMetrics.getRedisInfo()
    );

    return ResponseEntity.ok(metrics);
  }

  @PostMapping("/reset")
  @PreAuthorize("hasRole('ADMIN')")
  public ResponseEntity<String> resetMetrics() {
    statistics.reset();
    return ResponseEntity.ok("Metrics reset");
  }
}
```

### ❌ Cách sai

```java
// ❌ SAI 1: Không track metrics
@Cacheable("products")
public ProductDto getProduct(Long id) {
  // Không biết cache hit hay miss, không tune được
}

// ❌ SAI 2: Log mỗi request (quá verbose)
@Around("@annotation(Cacheable)")
public Object aroundCache(ProceedingJoinPoint pjp) {
  log.info("Cache GET for key: {}", key); // ❌ 10K requests/s = 10K logs/s
  // FIX: Dùng metrics, log aggregate (1 phút 1 lần)
}

// ❌ SAI 3: Metrics blocking I/O
@Scheduled(fixedRate = 1000)
public void collectMetrics() {
  RedisConnection conn = redis.getConnection();
  Properties info = conn.info(); // ❌ Blocking call mỗi giây
  // FIX: Collect mỗi 30-60s, dùng async
}

// ❌ SAI 4: Không set alert
// Hit rate xuống 30% → không ai biết → performance degradation
// FIX: Prometheus alert khi hit rate < 70%

// ❌ SAI 5: Metrics không tag
meterRegistry.counter("cache.hits").increment(); // ❌ Không biết cache nào
// FIX: .counter("cache.hits", "cache", cacheName)

// ❌ SAI 6: Không monitor Redis INFO stats
// Chỉ track app-level metrics → không biết Redis memory/eviction
// FIX: Collect redis.info() metrics

// ❌ SAI 7: Dashboard không có
// Có metrics nhưng không visualize → không actionable
// FIX: Setup Grafana dashboard
```

### Phát hiện

**Regex patterns:**
```regex
# @Cacheable không có metrics tracking
@Cacheable(?!.*@Around).*\n.*public

# Scheduled metrics collection quá frequent
@Scheduled\(fixedRate\s*=\s*[1-9]\d{0,2}\) # < 1000ms

# Metrics không có tags
meterRegistry\.counter\("[^"]+"\)\.increment\(\)(?!.*,)
```

**Checklist:**
```java
// 1. Enable Spring Boot Actuator metrics?
management.endpoints.web.exposure.include=metrics,prometheus // ✅

// 2. Register cache metrics?
CacheMetricsRegistrar.register(cacheManager, meterRegistry); // ✅

// 3. Track hit/miss rate?
@Around("@annotation(Cacheable)")
public Object track(ProceedingJoinPoint pjp) {
  // Record hit/miss
} // ✅

// 4. Monitor Redis INFO stats?
@Scheduled(fixedRate = 30000)
public void collectRedisMetrics() { } // ✅

// 5. Metrics có tags (cache name)?
meterRegistry.counter("cache.hits", "cache", cacheName); // ✅

// 6. Grafana dashboard setup?
# PromQL queries for hit rate, latency, eviction // ✅

// 7. Alert rules configured?
# Prometheus alert: cache_hit_rate < 0.7 // ✅

// 8. Health check includes cache?
@Component
public class CacheHealthIndicator implements HealthIndicator { } // ✅
```

---

## 10.08 - Multi-level cache (L1 local + L2 Redis) khi cần 🟡

### Metadata
- **ID:** `CACHE-008`
- **Mức độ:** 🟡 NÊN CÓ
- **Lý do:** L1 (Caffeine) < 1ms, L2 (Redis) ~5ms → giảm 80% Redis calls
- **Trade-off:** Invalidation phức tạp, memory overhead, consistency risk

### Tại sao?

**Vấn đề:**
- Redis network roundtrip: 3-10ms (LAN), 50-100ms (cross-region)
- High QPS (10K/s) → 10K Redis calls → network bottleneck
- Static data (categories, settings) query Redis không cần thiết

**Giải pháp: Multi-level cache**
- **L1 (local)**: Caffeine in-memory cache (< 1ms latency)
- **L2 (distributed)**: Redis cache (3-10ms latency)
- Read: L1 → L2 → DB
- Write: Invalidate L1 + L2

**Khi nào dùng:**
- ✅ Static/semi-static data (categories, configs)
- ✅ High read QPS (> 1000/s)
- ✅ Multi-instance app (dùng Redis pub/sub để sync L1)
- ❌ Real-time data (prices, inventory)
- ❌ Large objects (> 1MB) → chỉ dùng L2

### ✅ Cách đúng

```java
// ===== 1. Config Multi-level Cache =====
@Configuration
@EnableCaching
public class MultiLevelCacheConfig {

  @Bean
  public CacheManager cacheManager(
    RedisConnectionFactory redisConnectionFactory,
    RedisMessageListenerContainer listenerContainer
  ) {
    // L1: Caffeine local cache
    CaffeineCacheManager caffeineCacheManager = new CaffeineCacheManager();
    caffeineCacheManager.setCaffeine(Caffeine.newBuilder()
      .maximumSize(1000) // Max 1000 entries
      .expireAfterWrite(10, TimeUnit.MINUTES)
      .recordStats() // Enable metrics
    );

    // L2: Redis distributed cache
    RedisCacheConfiguration redisConfig = RedisCacheConfiguration
      .defaultCacheConfig()
      .entryTtl(Duration.ofHours(1))
      .serializeValuesWith(RedisSerializationContext.SerializationPair
        .fromSerializer(new GenericJackson2JsonRedisSerializer()));

    RedisCacheManager redisCacheManager = RedisCacheManager.builder(redisConnectionFactory)
      .cacheDefaults(redisConfig)
      .build();

    // Multi-level wrapper
    return new MultiLevelCacheManager(
      caffeineCacheManager,
      redisCacheManager,
      listenerContainer
    );
  }

  @Bean
  public RedisMessageListenerContainer redisMessageListenerContainer(
    RedisConnectionFactory connectionFactory
  ) {
    RedisMessageListenerContainer container = new RedisMessageListenerContainer();
    container.setConnectionFactory(connectionFactory);
    return container;
  }
}

// ===== 2. MultiLevelCacheManager Implementation =====
public class MultiLevelCacheManager implements CacheManager {

  private final CacheManager l1CacheManager; // Caffeine
  private final CacheManager l2CacheManager; // Redis
  private final RedisMessageListenerContainer listenerContainer;
  private final Map<String, MultiLevelCache> caches = new ConcurrentHashMap<>();

  public MultiLevelCacheManager(
    CacheManager l1,
    CacheManager l2,
    RedisMessageListenerContainer listenerContainer
  ) {
    this.l1CacheManager = l1;
    this.l2CacheManager = l2;
    this.listenerContainer = listenerContainer;
  }

  @Override
  public Cache getCache(String name) {
    return caches.computeIfAbsent(name, cacheName -> {
      Cache l1 = l1CacheManager.getCache(cacheName);
      Cache l2 = l2CacheManager.getCache(cacheName);
      return new MultiLevelCache(cacheName, l1, l2, listenerContainer);
    });
  }

  @Override
  public Collection<String> getCacheNames() {
    Set<String> names = new HashSet<>();
    names.addAll(l1CacheManager.getCacheNames());
    names.addAll(l2CacheManager.getCacheNames());
    return names;
  }
}

// ===== 3. MultiLevelCache Implementation =====
@Slf4j
public class MultiLevelCache implements Cache {

  private final String name;
  private final Cache l1Cache; // Caffeine
  private final Cache l2Cache; // Redis
  private final RedisMessageListenerContainer listenerContainer;
  private final String invalidationChannel;

  public MultiLevelCache(
    String name,
    Cache l1,
    Cache l2,
    RedisMessageListenerContainer listenerContainer
  ) {
    this.name = name;
    this.l1Cache = l1;
    this.l2Cache = l2;
    this.listenerContainer = listenerContainer;
    this.invalidationChannel = "cache:invalidate:" + name;

    // Subscribe to invalidation messages
    listenerContainer.addMessageListener(
      (message, pattern) -> {
        String key = new String(message.getBody());
        log.info("Received L1 invalidation for cache: {}, key: {}", name, key);
        if (l1Cache != null) {
          l1Cache.evict(key);
        }
      },
      new ChannelTopic(invalidationChannel)
    );
  }

  @Override
  public String getName() {
    return name;
  }

  @Override
  public Object getNativeCache() {
    return Map.of("l1", l1Cache, "l2", l2Cache);
  }

  @Override
  public ValueWrapper get(Object key) {
    // 1. Check L1
    ValueWrapper l1Value = l1Cache.get(key);
    if (l1Value != null) {
      log.debug("L1 cache HIT for key: {}", key);
      return l1Value;
    }

    // 2. Check L2
    ValueWrapper l2Value = l2Cache.get(key);
    if (l2Value != null) {
      log.debug("L2 cache HIT for key: {}, promoting to L1", key);
      // Promote to L1
      l1Cache.put(key, l2Value.get());
      return l2Value;
    }

    log.debug("Cache MISS (L1 + L2) for key: {}", key);
    return null;
  }

  @Override
  public <T> T get(Object key, Class<T> type) {
    ValueWrapper wrapper = get(key);
    return wrapper != null ? (T) wrapper.get() : null;
  }

  @Override
  public <T> T get(Object key, Callable<T> valueLoader) {
    ValueWrapper wrapper = get(key);
    if (wrapper != null) {
      return (T) wrapper.get();
    }

    // Load value
    try {
      T value = valueLoader.call();
      put(key, value);
      return value;
    } catch (Exception e) {
      throw new ValueRetrievalException(key, valueLoader, e);
    }
  }

  @Override
  public void put(Object key, Object value) {
    // Write to both levels
    l2Cache.put(key, value); // L2 first (persistent)
    l1Cache.put(key, value); // L1 second (fast)
    log.debug("Put to L1 + L2 cache, key: {}", key);
  }

  @Override
  public void evict(Object key) {
    // Evict from both levels
    l2Cache.evict(key);
    l1Cache.evict(key);

    // Broadcast invalidation to other instances
    publishInvalidation(key.toString());
    log.debug("Evicted from L1 + L2 cache, key: {}", key);
  }

  @Override
  public void clear() {
    l2Cache.clear();
    l1Cache.clear();
    publishInvalidation("*"); // Wildcard clear
    log.info("Cleared L1 + L2 cache: {}", name);
  }

  private void publishInvalidation(String key) {
    RedisConnection connection = null;
    try {
      connection = listenerContainer.getConnectionFactory().getConnection();
      connection.publish(
        invalidationChannel.getBytes(),
        key.getBytes()
      );
    } finally {
      if (connection != null) {
        connection.close();
      }
    }
  }
}

// ===== 4. Service Usage =====
@Service
public class ProductService {

  @Autowired
  private ProductRepository productRepository;

  // Multi-level cache tự động (qua CacheManager)
  @Cacheable(value = "products", key = "#id", unless = "#result == null")
  public ProductDto getProduct(Long id) {
    log.info("Querying DB for product: {}", id);
    return productRepository.findById(id)
      .map(this::toDto)
      .orElse(null);
  }

  @CacheEvict(value = "products", key = "#id")
  public ProductDto updateProduct(Long id, UpdateProductRequest request) {
    // Evict sẽ xóa L1 + L2 + broadcast invalidation
    Product product = productRepository.findById(id).orElseThrow();
    product.setName(request.name());
    return toDto(productRepository.save(product));
  }

  private ProductDto toDto(Product product) {
    return ProductDto.builder()
      .id(product.getId())
      .name(product.getName())
      .build();
  }
}

// ===== 5. Advanced: Conditional L1 caching =====
@Service
public class ConditionalMultiLevelService {

  @Autowired
  private CacheManager cacheManager;

  public ProductDto getProduct(Long id, boolean useL1) {
    String cacheKey = "product:" + id;

    if (useL1) {
      // Use multi-level cache
      Cache cache = cacheManager.getCache("products");
      return cache.get(cacheKey, ProductDto.class);
    } else {
      // Bypass L1, only use L2
      MultiLevelCache mlCache = (MultiLevelCache) cacheManager.getCache("products");
      Cache l2Only = (Cache) ((Map<?, ?>) mlCache.getNativeCache()).get("l2");
      return l2Only.get(cacheKey, ProductDto.class);
    }
  }
}

// ===== 6. Metrics per Level =====
@Component
@Slf4j
public class MultiLevelCacheMetrics {

  @Autowired
  private CacheManager cacheManager;

  @Autowired
  private MeterRegistry meterRegistry;

  @Scheduled(fixedRate = 60000)
  public void reportMetrics() {
    cacheManager.getCacheNames().forEach(cacheName -> {
      Cache cache = cacheManager.getCache(cacheName);

      if (cache instanceof MultiLevelCache mlCache) {
        Map<String, Cache> nativeCaches = (Map<String, Cache>) mlCache.getNativeCache();

        // L1 stats (Caffeine)
        Cache l1 = nativeCaches.get("l1");
        if (l1.getNativeCache() instanceof com.github.benmanes.caffeine.cache.Cache caffeine) {
          com.github.benmanes.caffeine.cache.stats.CacheStats stats = caffeine.stats();

          meterRegistry.gauge("cache.l1.hit.rate", stats.hitRate());
          meterRegistry.gauge("cache.l1.miss.rate", stats.missRate());
          meterRegistry.gauge("cache.l1.eviction.count", stats.evictionCount());

          log.info("L1 Cache [{}] - Hit Rate: {:.2f}%, Evictions: {}",
            cacheName,
            stats.hitRate() * 100,
            stats.evictionCount()
          );
        }
      }
    });
  }
}

// ===== Dependencies: pom.xml =====
/*
<dependency>
  <groupId>com.github.ben-manes.caffeine</groupId>
  <artifactId>caffeine</artifactId>
  <version>3.1.8</version>
</dependency>
*/
```

### ❌ Cách sai

```java
// ❌ SAI 1: L1 không có TTL
Caffeine.newBuilder()
  .maximumSize(10000); // ❌ Không expire → stale data mãi mãi
// FIX: Thêm .expireAfterWrite(10, TimeUnit.MINUTES)

// ❌ SAI 2: Không invalidate L1 khi evict L2
@CacheEvict(value = "products", key = "#id")
public void updateProduct(Long id) {
  // ❌ Chỉ evict Redis, L1 vẫn giữ data cũ
}
// FIX: MultiLevelCache.evict() phải evict cả 2

// ❌ SAI 3: Không broadcast invalidation (multi-instance)
public void evict(Object key) {
  l1Cache.evict(key);
  l2Cache.evict(key);
  // ❌ Instance 2, 3 vẫn giữ data cũ trong L1
}
// FIX: Publish Redis message để sync

// ❌ SAI 4: L1 size quá lớn
Caffeine.newBuilder()
  .maximumSize(1_000_000); // ❌ 1M entries → OutOfMemoryError
// FIX: Size < 10K cho most apps

// ❌ SAI 5: Cache large objects trong L1
@Cacheable("reports") // L1 + L2
public byte[] generateReport(Long id) {
  return new byte[50 * 1024 * 1024]; // ❌ 50MB per entry
}
// FIX: Large objects chỉ cache L2 (Redis), skip L1

// ❌ SAI 6: Không monitor L1 hit rate
// L1 hit rate thấp (< 50%) → không cần L1, tốn memory vô ích
// FIX: Track metrics, disable L1 nếu không effective

// ❌ SAI 7: L1 + L2 cùng TTL
L1: expireAfterWrite(1, TimeUnit.HOURS)
L2: entryTtl(Duration.ofHours(1))
// ❌ L1 expire → L2 promote → L1 expire lại → thrashing
// FIX: L1 TTL ngắn hơn L2 (L1: 10min, L2: 1 hour)
```

### Phát hiện

**Regex patterns:**
```regex
# Caffeine không có expire
Caffeine\.newBuilder\(\).*maximumSize(?!.*expireAfter)

# @CacheEvict không broadcast
@CacheEvict.*\n.*public.*update(?!.*publish|broadcast)

# L1 size quá lớn
maximumSize\(([1-9]\d{5,})\) # > 100K

# Large object cache trong L1
@Cacheable.*\n.*public\s+byte\[\]
```

**Checklist:**
```java
// 1. L1 có TTL?
Caffeine.newBuilder()
  .expireAfterWrite(10, TimeUnit.MINUTES) // ✅

// 2. L1 size hợp lý (< 10K)?
.maximumSize(1000) // ✅

// 3. Evict cả L1 + L2?
@Override
public void evict(Object key) {
  l1Cache.evict(key);
  l2Cache.evict(key);
} // ✅

// 4. Broadcast invalidation?
publishInvalidation(key.toString()); // ✅

// 5. L1 TTL < L2 TTL?
L1: 10 minutes, L2: 1 hour // ✅

// 6. Monitor L1 hit rate?
@Scheduled
public void reportL1Metrics() {
  CacheStats stats = caffeine.stats();
  log.info("L1 Hit Rate: {}", stats.hitRate());
} // ✅

// 7. Large objects skip L1?
if (size > 1MB) {
  l2Cache.put(key, value); // Only L2
} else {
  put(key, value); // L1 + L2
} // ✅

// 8. Test multi-instance invalidation?
@Test
void testCrossInstanceInvalidation() {
  // Instance 1: put(key, value)
  // Instance 2: evict(key)
  // Instance 1: get(key) → null ✅
}
```

---

**End of Domain 10: Caching**
