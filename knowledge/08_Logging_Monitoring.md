# Domain 08: Logging & Monitoring

> **Số practices:** 9 | 🔴 1 | 🟠 5 | 🟡 3
> **Trọng số:** ×1

---

## 08.01 - Structured logging (JSON format) với SLF4J + Logback

### Metadata
- **ID:** `08.01`
- **Mức độ:** 🟠 KHUYẾN NGHỊ
- **Lý do:** Dễ parse, search, aggregate trong log management systems (ELK, Splunk)

### Tại sao?

**Vấn đề với plain text logs:**
```
2026-02-16 10:30:45 INFO User john@example.com logged in from 192.168.1.100
```
- Khó parse bằng regex
- Không có metadata cấu trúc
- Khó filter theo fields cụ thể

**Lợi ích JSON logging:**
- Machine-readable format
- Dễ index và search trong log aggregators
- Chứa rich metadata (timestamp, level, thread, MDC context)
- Support cho distributed tracing

### ✅ Cách đúng

**Dependencies (pom.xml):**
```xml
<dependencies>
  <!-- SLF4J API -->
  <dependency>
    <groupId>org.slf4j</groupId>
    <artifactId>slf4j-api</artifactId>
  </dependency>

  <!-- Logback with JSON support -->
  <dependency>
    <groupId>ch.qos.logback</groupId>
    <artifactId>logback-classic</artifactId>
  </dependency>
  <dependency>
    <groupId>net.logstash.logback</groupId>
    <artifactId>logstash-logback-encoder</artifactId>
    <version>7.4</version>
  </dependency>
</dependencies>
```

**Logback configuration (src/main/resources/logback-spring.xml):**
```xml
<configuration>
  <springProperty scope="context" name="APP_NAME" source="spring.application.name"/>

  <!-- Console appender với JSON format -->
  <appender name="CONSOLE_JSON" class="ch.qos.logback.core.ConsoleAppender">
    <encoder class="net.logstash.logback.encoder.LogstashEncoder">
      <customFields>{"app":"${APP_NAME}"}</customFields>
      <includeMdcKeyNames>requestId,userId,sessionId,traceId,spanId</includeMdcKeyNames>
      <fieldNames>
        <timestamp>@timestamp</timestamp>
        <message>message</message>
        <logger>logger_name</logger>
        <thread>thread_name</thread>
        <level>level</level>
        <levelValue>[ignore]</levelValue>
      </fieldNames>
    </encoder>
  </appender>

  <!-- File appender với JSON format -->
  <appender name="FILE_JSON" class="ch.qos.logback.core.rolling.RollingFileAppender">
    <file>logs/application.json</file>
    <rollingPolicy class="ch.qos.logback.core.rolling.SizeAndTimeBasedRollingPolicy">
      <fileNamePattern>logs/application-%d{yyyy-MM-dd}.%i.json.gz</fileNamePattern>
      <maxFileSize>100MB</maxFileSize>
      <maxHistory>30</maxHistory>
      <totalSizeCap>10GB</totalSizeCap>
    </rollingPolicy>
    <encoder class="net.logstash.logback.encoder.LogstashEncoder">
      <customFields>{"app":"${APP_NAME}"}</customFields>
      <includeMdcKeyNames>requestId,userId,sessionId,traceId,spanId</includeMdcKeyNames>
    </encoder>
  </appender>

  <root level="INFO">
    <appender-ref ref="CONSOLE_JSON"/>
    <appender-ref ref="FILE_JSON"/>
  </root>
</configuration>
```

**Sử dụng structured logging:**
```java
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import net.logstash.logback.argument.StructuredArguments;
import static net.logstash.logback.argument.StructuredArguments.*;

@Service
public class OrderService {
  private static final Logger log = LoggerFactory.getLogger(OrderService.class);

  public Order createOrder(CreateOrderRequest request) {
    log.info("Creating order",
      keyValue("customerId", request.customerId()),
      keyValue("totalAmount", request.totalAmount()),
      keyValue("itemCount", request.items().size())
    );

    try {
      Order order = orderRepository.save(toEntity(request));

      log.info("Order created successfully",
        keyValue("orderId", order.getId()),
        keyValue("status", order.getStatus()),
        keyValue("createdAt", order.getCreatedAt())
      );

      return order;
    } catch (Exception e) {
      log.error("Failed to create order",
        keyValue("customerId", request.customerId()),
        keyValue("error", e.getMessage()),
        e
      );
      throw e;
    }
  }
}
```

**JSON output:**
```json
{
  "@timestamp": "2026-02-16T10:30:45.123+07:00",
  "message": "Creating order",
  "logger_name": "jp.medicalbox.service.OrderService",
  "thread_name": "http-nio-8080-exec-1",
  "level": "INFO",
  "app": "jr-medicalbox-api",
  "customerId": 12345,
  "totalAmount": 150000,
  "itemCount": 3,
  "requestId": "abc123",
  "userId": "user@example.com",
  "traceId": "6e0c63257de34c92bf9efcd03927272e"
}
```

### ❌ Cách sai

**Plain text logging (khó parse):**
```java
// ❌ Khó parse, không có structured fields
log.info("User {} logged in from IP {} at {}",
  username, ipAddress, LocalDateTime.now());

// ❌ String concatenation trong log
log.info("Order created: " + order.getId() + " for customer: " + customerId);

// ❌ Không có context fields
log.error("Payment failed", exception);
```

**Logback configuration không tối ưu:**
```xml
<!-- ❌ Plain pattern, không có JSON -->
<appender name="CONSOLE" class="ch.qos.logback.core.ConsoleAppender">
  <encoder>
    <pattern>%d{HH:mm:ss.SSS} [%thread] %-5level %logger{36} - %msg%n</pattern>
  </encoder>
</appender>
```

### Phát hiện (ripgrep)

```bash
# Tìm plain text logging patterns
rg "new PatternLayoutEncoder" src/main/resources/

# Tìm string concatenation trong logs
rg 'log\.(info|warn|error|debug)\([^,]*\+' --type java

# Kiểm tra có logstash-logback-encoder không
rg "logstash-logback-encoder" pom.xml
```

### Checklist

- [ ] Dependencies có `logstash-logback-encoder`
- [ ] Logback config sử dụng `LogstashEncoder`
- [ ] Console và file appenders đều dùng JSON format
- [ ] Custom fields include app name, environment
- [ ] MDC keys được include trong JSON output
- [ ] Log messages sử dụng `StructuredArguments.keyValue()`
- [ ] Không có string concatenation trong log statements

---

## 08.02 - MDC cho request tracing (requestId, userId, sessionId)

### Metadata
- **ID:** `08.02`
- **Mức độ:** 🟠 KHUYẾN NGHỊ
- **Lý do:** Trace được toàn bộ flow của 1 request qua nhiều services/threads

### Tại sao?

**Vấn đề khi không có MDC:**
- Logs từ nhiều requests bị xen kẽ nhau
- Không trace được flow của 1 user journey
- Khó debug distributed systems
- Không biết log nào thuộc request nào

**Lợi ích MDC (Mapped Diagnostic Context):**
- Tự động attach context vào mọi log statement
- Trace request từ đầu đến cuối
- Support distributed tracing (traceId, spanId)
- Dễ filter logs theo user, session, request

### ✅ Cách đúng

**MDC Filter:**
```java
import org.slf4j.MDC;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.util.UUID;

@Component
@Order(1) // Chạy đầu tiên trong filter chain
public class MdcFilter implements Filter {
  private static final String REQUEST_ID = "requestId";
  private static final String USER_ID = "userId";
  private static final String SESSION_ID = "sessionId";
  private static final String IP_ADDRESS = "ipAddress";
  private static final String USER_AGENT = "userAgent";

  @Override
  public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
      throws IOException, ServletException {
    HttpServletRequest httpRequest = (HttpServletRequest) request;

    try {
      // Request ID: từ header hoặc generate mới
      String requestId = httpRequest.getHeader("X-Request-ID");
      if (requestId == null || requestId.isBlank()) {
        requestId = UUID.randomUUID().toString();
      }
      MDC.put(REQUEST_ID, requestId);

      // User ID: từ SecurityContext (sau authentication)
      String userId = getCurrentUserId();
      if (userId != null) {
        MDC.put(USER_ID, userId);
      }

      // Session ID
      String sessionId = httpRequest.getSession(false) != null
        ? httpRequest.getSession().getId()
        : null;
      if (sessionId != null) {
        MDC.put(SESSION_ID, sessionId);
      }

      // IP Address
      String ipAddress = getClientIpAddress(httpRequest);
      MDC.put(IP_ADDRESS, ipAddress);

      // User Agent
      String userAgent = httpRequest.getHeader("User-Agent");
      if (userAgent != null) {
        MDC.put(USER_AGENT, userAgent);
      }

      chain.doFilter(request, response);
    } finally {
      // QUAN TRỌNG: Clear MDC sau khi request hoàn thành
      MDC.clear();
    }
  }

  private String getCurrentUserId() {
    try {
      Authentication auth = SecurityContextHolder.getContext().getAuthentication();
      if (auth != null && auth.isAuthenticated() && !(auth instanceof AnonymousAuthenticationToken)) {
        return auth.getName();
      }
    } catch (Exception e) {
      // Ignore
    }
    return null;
  }

  private String getClientIpAddress(HttpServletRequest request) {
    String xForwardedFor = request.getHeader("X-Forwarded-For");
    if (xForwardedFor != null && !xForwardedFor.isBlank()) {
      return xForwardedFor.split(",")[0].trim();
    }
    return request.getRemoteAddr();
  }
}
```

**Async tasks cần copy MDC:**
```java
import org.slf4j.MDC;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

@Service
public class NotificationService {
  private static final Logger log = LoggerFactory.getLogger(NotificationService.class);

  @Async
  public CompletableFuture<Void> sendEmailAsync(String recipient, String subject) {
    // Copy MDC từ parent thread
    Map<String, String> mdcContext = MDC.getCopyOfContextMap();

    return CompletableFuture.runAsync(() -> {
      try {
        // Set MDC trong async thread
        if (mdcContext != null) {
          MDC.setContextMap(mdcContext);
        }

        log.info("Sending email",
          keyValue("recipient", recipient),
          keyValue("subject", subject)
        );

        // Email sending logic...

        log.info("Email sent successfully");
      } finally {
        MDC.clear();
      }
    });
  }
}
```

**TaskDecorator cho ThreadPoolTaskExecutor:**
```java
import org.slf4j.MDC;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.task.TaskDecorator;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;
import java.util.Map;

@Configuration
@EnableAsync
public class AsyncConfig {

  @Bean(name = "taskExecutor")
  public ThreadPoolTaskExecutor taskExecutor() {
    ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();
    executor.setCorePoolSize(5);
    executor.setMaxPoolSize(10);
    executor.setQueueCapacity(100);
    executor.setThreadNamePrefix("async-");
    executor.setTaskDecorator(new MdcTaskDecorator());
    executor.initialize();
    return executor;
  }

  static class MdcTaskDecorator implements TaskDecorator {
    @Override
    public Runnable decorate(Runnable runnable) {
      Map<String, String> contextMap = MDC.getCopyOfContextMap();
      return () -> {
        try {
          if (contextMap != null) {
            MDC.setContextMap(contextMap);
          }
          runnable.run();
        } finally {
          MDC.clear();
        }
      };
    }
  }
}
```

**RestTemplate interceptor để propagate MDC:**
```java
import org.slf4j.MDC;
import org.springframework.http.HttpRequest;
import org.springframework.http.client.ClientHttpRequestExecution;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.http.client.ClientHttpResponse;
import java.io.IOException;

public class MdcPropagatingInterceptor implements ClientHttpRequestInterceptor {

  @Override
  public ClientHttpResponse intercept(
      HttpRequest request,
      byte[] body,
      ClientHttpRequestExecution execution) throws IOException {

    // Propagate requestId qua HTTP header
    String requestId = MDC.get("requestId");
    if (requestId != null) {
      request.getHeaders().add("X-Request-ID", requestId);
    }

    String traceId = MDC.get("traceId");
    if (traceId != null) {
      request.getHeaders().add("X-Trace-ID", traceId);
    }

    return execution.execute(request, body);
  }
}
```

**Logback configuration để include MDC:**
```xml
<configuration>
  <appender name="CONSOLE_JSON" class="ch.qos.logback.core.ConsoleAppender">
    <encoder class="net.logstash.logback.encoder.LogstashEncoder">
      <!-- Include MDC keys -->
      <includeMdcKeyNames>
        requestId,userId,sessionId,ipAddress,userAgent,traceId,spanId
      </includeMdcKeyNames>
    </encoder>
  </appender>
</configuration>
```

### ❌ Cách sai

```java
// ❌ Không clear MDC trong finally (memory leak)
@Override
public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) {
  MDC.put("requestId", UUID.randomUUID().toString());
  chain.doFilter(request, response);
  // Missing MDC.clear()!
}

// ❌ Async task không copy MDC
@Async
public void processAsync() {
  log.info("Processing"); // MDC context bị mất!
}

// ❌ Manual logging thay vì dùng MDC
log.info("Request {} from user {}", requestId, userId); // Nên dùng MDC
```

### Phát hiện (ripgrep)

```bash
# Tìm MDC.put() không có MDC.clear()
rg "MDC\.put\(" --type java -A 20 | rg -v "MDC\.clear\(\)"

# Tìm @Async methods không copy MDC
rg "@Async" --type java -A 10 | rg -v "getCopyOfContextMap"

# Kiểm tra có MdcFilter không
rg "class.*Filter.*MDC" --type java
```

### Checklist

- [ ] Có `MdcFilter` chạy đầu tiên (`@Order(1)`)
- [ ] MDC.clear() trong `finally` block
- [ ] Async tasks copy MDC context
- [ ] ThreadPoolTaskExecutor có `MdcTaskDecorator`
- [ ] RestTemplate có interceptor propagate requestId
- [ ] Logback config include MDC keys
- [ ] RequestId từ header hoặc auto-generate

---

## 08.03 - Log levels đúng mục đích (ERROR/WARN/INFO/DEBUG/TRACE)

### Metadata
- **ID:** `08.03`
- **Mức độ:** 🟠 KHUYẾN NGHỊ
- **Lý do:** Tránh log spam, dễ troubleshoot production issues

### Tại sao?

**Vấn đề khi dùng log level sai:**
- Production đầy INFO logs vô nghĩa → khó tìm issues
- ERROR cho non-critical issues → false alarms
- DEBUG logs chạy trên production → performance impact
- Không biết log nào quan trọng

**Lợi ích log levels đúng:**
- Production chỉ có INFO trở lên (ít noise)
- Alerts chỉ trigger cho ERROR/WARN
- Debug dễ hơn khi enable DEBUG level
- Performance tốt hơn

### ✅ Cách đúng

**Log level guidelines:**

**ERROR** - System errors, cần intervention ngay:
```java
@Service
public class PaymentService {
  private static final Logger log = LoggerFactory.getLogger(PaymentService.class);

  public Payment processPayment(PaymentRequest request) {
    try {
      return paymentGateway.charge(request);
    } catch (PaymentGatewayException e) {
      // ERROR: External service failure, cần investigate
      log.error("Payment gateway failed",
        keyValue("orderId", request.orderId()),
        keyValue("amount", request.amount()),
        keyValue("gateway", request.gateway()),
        keyValue("errorCode", e.getErrorCode()),
        e
      );
      throw new PaymentFailedException("Payment processing failed", e);
    } catch (InsufficientFundsException e) {
      // KHÔNG PHẢI ERROR: Business logic failure (expected)
      log.warn("Insufficient funds",
        keyValue("orderId", request.orderId()),
        keyValue("customerId", request.customerId())
      );
      throw e;
    }
  }
}
```

**WARN** - Unexpected nhưng không critical:
```java
@Service
public class CacheService {
  private static final Logger log = LoggerFactory.getLogger(CacheService.class);

  public <T> T getOrLoad(String key, Supplier<T> loader) {
    try {
      T cached = redisTemplate.opsForValue().get(key);
      if (cached != null) {
        return cached;
      }
    } catch (Exception e) {
      // WARN: Cache miss không critical, fallback to DB
      log.warn("Redis cache error, falling back to DB",
        keyValue("key", key),
        keyValue("error", e.getMessage())
      );
    }

    T value = loader.get();

    try {
      redisTemplate.opsForValue().set(key, value, Duration.ofMinutes(10));
    } catch (Exception e) {
      // WARN: Cache write failed, không ảnh hưởng business logic
      log.warn("Failed to cache value",
        keyValue("key", key),
        keyValue("error", e.getMessage())
      );
    }

    return value;
  }
}
```

**INFO** - Important business events:
```java
@Service
public class OrderService {
  private static final Logger log = LoggerFactory.getLogger(OrderService.class);

  public Order createOrder(CreateOrderRequest request) {
    // INFO: Important business event
    log.info("Creating order",
      keyValue("customerId", request.customerId()),
      keyValue("totalAmount", request.totalAmount())
    );

    Order order = orderRepository.save(toEntity(request));

    // INFO: Order state change
    log.info("Order created",
      keyValue("orderId", order.getId()),
      keyValue("status", order.getStatus())
    );

    return order;
  }

  public void updateOrderStatus(Long orderId, OrderStatus newStatus) {
    Order order = orderRepository.findById(orderId)
      .orElseThrow(() -> new OrderNotFoundException(orderId));

    OrderStatus oldStatus = order.getStatus();
    order.setStatus(newStatus);
    orderRepository.save(order);

    // INFO: State transition
    log.info("Order status updated",
      keyValue("orderId", orderId),
      keyValue("oldStatus", oldStatus),
      keyValue("newStatus", newStatus)
    );
  }
}
```

**DEBUG** - Detailed flow information (development/troubleshooting):
```java
@Service
public class AuthService {
  private static final Logger log = LoggerFactory.getLogger(AuthService.class);

  public AuthResponse login(LoginRequest request) {
    log.debug("Login attempt", keyValue("email", request.email()));

    User user = userRepository.findByEmail(request.email())
      .orElseThrow(() -> new InvalidCredentialsException());

    log.debug("User found", keyValue("userId", user.getId()));

    if (!passwordEncoder.matches(request.password(), user.getPasswordHash())) {
      log.debug("Password mismatch", keyValue("userId", user.getId()));
      throw new InvalidCredentialsException();
    }

    log.debug("Password verified", keyValue("userId", user.getId()));

    String token = jwtService.generateToken(user);

    log.debug("Token generated",
      keyValue("userId", user.getId()),
      keyValue("tokenLength", token.length())
    );

    log.info("Login successful", keyValue("userId", user.getId()));

    return new AuthResponse(token, user);
  }
}
```

**TRACE** - Very detailed (method entry/exit):
```java
@Aspect
@Component
public class LoHttpStatusgging {
  private static final Logger log = LoggerFactory.getLogger(LoggingAspect.class);

  @Around("@annotation(Loggable)")
  public Object logMethodExecution(ProceedingJoinPoint joinPoint) throws Throwable {
    String methodName = joinPoint.getSignature().toShortString();
    Object[] args = joinPoint.getArgs();

    log.trace("Method entry: {}", methodName, keyValue("args", args));

    long startTime = System.currentTimeMillis();
    try {
      Object result = joinPoint.proceed();
      long duration = System.currentTimeMillis() - startTime;

      log.trace("Method exit: {}",
        methodName,
        keyValue("duration", duration),
        keyValue("result", result)
      );

      return result;
    } catch (Exception e) {
      long duration = System.currentTimeMillis() - startTime;
      log.trace("Method exception: {}",
        methodName,
        keyValue("duration", duration),
        e
      );
      throw e;
    }
  }
}
```

**Configuration theo environment:**
```yaml
# application.yml (default)
logging:
  level:
    root: INFO
    jp.medicalbox: INFO
    org.springframework.web: WARN
    org.hibernate.SQL: WARN

# application-dev.yml
logging:
  level:
    root: INFO
    jp.medicalbox: DEBUG
    org.springframework.web: DEBUG
    org.hibernate.SQL: DEBUG
    org.hibernate.type.descriptor.sql.BasicBinder: TRACE

# application-prod.yml
logging:
  level:
    root: WARN
    jp.medicalbox: INFO
    org.springframework.web: ERROR
    org.hibernate.SQL: WARN
```

**Conditional logging để tránh performance hit:**
```java
@Service
public class DataProcessor {
  private static final Logger log = LoggerFactory.getLogger(DataProcessor.class);

  public void processLargeDataset(List<Record> records) {
    // ❌ BAD: String concatenation chạy dù DEBUG tắt
    // log.debug("Processing records: " + records.toString());

    // ✅ GOOD: Check isDebugEnabled() trước
    if (log.isDebugEnabled()) {
      log.debug("Processing records",
        keyValue("count", records.size()),
        keyValue("firstRecord", records.get(0))
      );
    }

    // Process records...
  }
}
```

### ❌ Cách sai

```java
// ❌ ERROR cho business validation failures
if (order.getTotalAmount() < 0) {
  log.error("Invalid order amount"); // Nên dùng WARN
  throw new InvalidOrderException();
}

// ❌ INFO cho quá nhiều details
log.info("SQL query: {}", sqlQuery); // Nên dùng DEBUG

// ❌ DEBUG cho critical errors
try {
  paymentGateway.charge(request);
} catch (Exception e) {
  log.debug("Payment failed", e); // Nên dùng ERROR!
}

// ❌ String concatenation khi log disabled
log.debug("Data: " + expensiveOperation()); // Vẫn chạy expensiveOperation()!

// ❌ Production có DEBUG level
# application-prod.yml
logging:
  level:
    root: DEBUG # Too verbose!
```

### Phát hiện (ripgrep)

```bash
# Tìm log.error() cho validation failures
rg 'log\.error.*Invalid|log\.error.*Bad request' --type java

# Tìm log.info() với SQL queries
rg 'log\.info.*SQL|log\.info.*query' --type java

# Tìm string concatenation trong logs
rg 'log\.(debug|trace)\([^)]*\+' --type java

# Kiểm tra production log levels
rg "level:.*DEBUG" src/main/resources/application-prod.yml
```

### Checklist

- [ ] ERROR chỉ cho system failures (cần investigate)
- [ ] WARN cho unexpected nhưng recoverable issues
- [ ] INFO cho important business events
- [ ] DEBUG cho detailed troubleshooting info
- [ ] TRACE cho method-level tracing
- [ ] Production config: root=WARN, app=INFO
- [ ] Development config: app=DEBUG
- [ ] Conditional logging cho expensive operations

---

## 08.04 - Không log sensitive data (password, token, card number)

### Metadata
- **ID:** `08.04`
- **Mức độ:** 🔴 BẮT BUỘC
- **Lý do:** Compliance (GDPR, PCI-DSS), security breach prevention

### Tại sao?

**Hậu quả khi log sensitive data:**
- Vi phạm GDPR (phạt đến 4% doanh thu)
- Vi phạm PCI-DSS (mất quyền process payments)
- Logs bị leak → credential theft
- Regulatory audit failures

**Data cần bảo vệ:**
- Passwords, tokens, API keys
- Credit card numbers, CVV
- SSN, passport numbers
- Personal health information (PHI)
- IP addresses (GDPR personal data)

### ✅ Cách đúng

**Sensitive data masking:**
```java
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Service
public class AuthService {
  private static final Logger log = LoggerFactory.getLogger(AuthService.class);

  public AuthResponse login(LoginRequest request) {
    // ✅ Chỉ log email, KHÔNG log password
    log.info("Login attempt", keyValue("email", request.email()));

    // Validate credentials...
    User user = authenticate(request.email(), request.password());

    String token = jwtService.generateToken(user);

    // ✅ Không log full token, chỉ log prefix
    log.info("Login successful",
      keyValue("userId", user.getId()),
      keyValue("tokenPrefix", maskToken(token))
    );

    return new AuthResponse(token, user);
  }

  private String maskToken(String token) {
    if (token == null || token.length() < 10) {
      return "***";
    }
    return token.substring(0, 10) + "...";
  }
}
```

**DTO với @JsonIgnore cho sensitive fields:**
```java
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;

public record CreateUserRequest(
  String email,

  @JsonProperty(access = JsonProperty.Access.WRITE_ONLY)
  String password, // Không serialize khi log

  String firstName,
  String lastName,

  @JsonIgnore
  String ssn // Never serialize
) {
  @Override
  public String toString() {
    // ✅ Custom toString() để mask sensitive data
    return "CreateUserRequest{" +
      "email='" + email + '\'' +
      ", password='***'" +
      ", firstName='" + firstName + '\'' +
      ", lastName='" + lastName + '\'' +
      ", ssn='***'" +
      '}';
  }
}
```

**Credit card masking:**
```java
@Service
public class PaymentService {
  private static final Logger log = LoggerFactory.getLogger(PaymentService.class);

  public Payment processPayment(PaymentRequest request) {
    // ✅ Mask card number
    log.info("Processing payment",
      keyValue("customerId", request.customerId()),
      keyValue("amount", request.amount()),
      keyValue("cardNumber", maskCardNumber(request.cardNumber()))
    );

    // Process payment...
  }

  private String maskCardNumber(String cardNumber) {
    if (cardNumber == null || cardNumber.length() < 4) {
      return "****";
    }
    // Show only last 4 digits
    return "**** **** **** " + cardNumber.substring(cardNumber.length() - 4);
  }
}
```

**Logback masking patterns:**
```xml
<configuration>
  <appender name="CONSOLE_JSON" class="ch.qos.logback.core.ConsoleAppender">
    <encoder class="net.logstash.logback.encoder.LogstashEncoder">
      <!-- Mask sensitive fields trong JSON -->
      <jsonGeneratorDecorator class="net.logstash.logback.mask.MaskingJsonGeneratorDecorator">
        <defaultMask>***</defaultMask>
        <path>password</path>
        <path>token</path>
        <path>accessToken</path>
        <path>refreshToken</path>
        <path>apiKey</path>
        <path>ssn</path>
        <path>cardNumber</path>
        <path>cvv</path>
      </jsonGeneratorDecorator>
    </encoder>
  </appender>
</configuration>
```

**Custom masking utility:**
```java
public class SensitiveDataMasker {

  private static final Pattern EMAIL_PATTERN = Pattern.compile(
    "([a-zA-Z0-9._%+-]+)@([a-zA-Z0-9.-]+\\.[a-zA-Z]{2,})"
  );

  private static final Pattern CARD_PATTERN = Pattern.compile(
    "\\b\\d{4}[\\s-]?\\d{4}[\\s-]?\\d{4}[\\s-]?\\d{4}\\b"
  );

  public static String maskEmail(String email) {
    if (email == null || email.isBlank()) {
      return "***";
    }

    Matcher matcher = EMAIL_PATTERN.matcher(email);
    if (!matcher.matches()) {
      return email;
    }

    String localPart = matcher.group(1);
    String domain = matcher.group(2);

    if (localPart.length() <= 2) {
      return "**@" + domain;
    }

    return localPart.charAt(0) + "***@" + domain;
  }

  public static String maskCardNumber(String cardNumber) {
    if (cardNumber == null || cardNumber.isBlank()) {
      return "****";
    }

    String digits = cardNumber.replaceAll("[\\s-]", "");
    if (digits.length() < 4) {
      return "****";
    }

    return "**** **** **** " + digits.substring(digits.length() - 4);
  }

  public static String maskToken(String token) {
    if (token == null || token.length() < 10) {
      return "***";
    }
    return token.substring(0, 8) + "...";
  }

  public static String maskIpAddress(String ip) {
    if (ip == null || ip.isBlank()) {
      return "***";
    }

    String[] parts = ip.split("\\.");
    if (parts.length != 4) {
      return "***";
    }

    return parts[0] + "." + parts[1] + ".***.***";
  }
}
```

**Request/Response logging filter:**
```java
import org.springframework.web.filter.CommonsRequestLoggingFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class LoggingConfig {

  @Bean
  public CommonsRequestLoggingFilter requestLoggingFilter() {
    CommonsRequestLoggingFilter filter = new SensitiveDataLoggingFilter();
    filter.setIncludeQueryString(true);
    filter.setIncludePayload(true);
    filter.setMaxPayloadLength(10000);
    filter.setIncludeHeaders(true);
    filter.setAfterMessagePrefix("REQUEST: ");
    return filter;
  }

  static class SensitiveDataLoggingFilter extends CommonsRequestLoggingFilter {
    private static final List<String> SENSITIVE_HEADERS = List.of(
      "authorization",
      "cookie",
      "x-api-key",
      "x-auth-token"
    );

    @Override
    protected void beforeRequest(HttpServletRequest request, String message) {
      // Mask sensitive headers
      String masked = maskSensitiveData(message);
      super.beforeRequest(request, masked);
    }

    private String maskSensitiveData(String message) {
      String result = message;

      // Mask passwords trong query/payload
      result = result.replaceAll(
        "(?i)(password|pwd|secret)=([^&\\s]+)",
        "$1=***"
      );

      // Mask tokens
      result = result.replaceAll(
        "(?i)(token|apikey|api_key)=([^&\\s]+)",
        "$1=***"
      );

      // Mask Authorization header
      result = result.replaceAll(
        "(?i)(authorization|cookie):\\s*[^\\r\\n]+",
        "$1: ***"
      );

      return result;
    }
  }
}
```

**Aspect-based masking:**
```java
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.springframework.stereotype.Component;

@Aspect
@Component
public class SensitiveDataLoggingAspect {
  private static final Logger log = LoggerFactory.getLogger(SensitiveDataLoggingAspect.class);

  @Around("@annotation(LogMethodCall)")
  public Object logMethodCall(ProceedingJoinPoint joinPoint) throws Throwable {
    String methodName = joinPoint.getSignature().toShortString();
    Object[] args = maskSensitiveArguments(joinPoint.getArgs());

    log.info("Method called: {}", methodName, keyValue("args", args));

    try {
      Object result = joinPoint.proceed();
      log.info("Method completed: {}", methodName);
      return result;
    } catch (Exception e) {
      log.error("Method failed: {}", methodName, e);
      throw e;
    }
  }

  private Object[] maskSensitiveArguments(Object[] args) {
    if (args == null) {
      return null;
    }

    Object[] masked = new Object[args.length];
    for (int i = 0; i < args.length; i++) {
      masked[i] = maskIfSensitive(args[i]);
    }
    return masked;
  }

  private Object maskIfSensitive(Object arg) {
    if (arg == null) {
      return null;
    }

    // Mask password fields
    if (arg.getClass().getSimpleName().contains("Password")) {
      return "***";
    }

    // Mask token fields
    if (arg instanceof String && ((String) arg).length() > 100) {
      return SensitiveDataMasker.maskToken((String) arg);
    }

    return arg;
  }
}
```

### ❌ Cách sai

```java
// ❌ Log password plaintext
log.info("User login", keyValue("password", request.password()));

// ❌ Log full token
log.info("Token generated", keyValue("token", jwtToken));

// ❌ Log credit card number
log.info("Payment", keyValue("cardNumber", request.cardNumber()));

// ❌ Log SSN
log.info("User created", keyValue("ssn", user.getSsn()));

// ❌ Log API key
log.info("External API call", keyValue("apiKey", apiKey));

// ❌ toString() expose sensitive data
@Override
public String toString() {
  return "User{password='" + password + "'}"; // Leaked!
}

// ❌ Exception message chứa sensitive data
throw new RuntimeException("Login failed for password: " + password);
```

### Phát hiện (ripgrep)

```bash
# Tìm log statements với password/token/ssn
rg 'log\.(info|warn|error|debug).*password|token|ssn|cardNumber|cvv' --type java -i

# Tìm toString() có thể leak data
rg '@Override.*toString.*password|token|ssn' --type java -A 5

# Tìm Exception messages với sensitive data
rg 'throw new.*Exception.*password|token|apiKey' --type java

# Kiểm tra @JsonIgnore cho sensitive fields
rg 'String (password|token|ssn|cardNumber)' --type java | rg -v '@JsonIgnore'
```

### Checklist

- [ ] Không log passwords, tokens, API keys
- [ ] Credit card numbers được mask (chỉ hiện 4 số cuối)
- [ ] SSN, passport numbers không log
- [ ] Email addresses được mask (GDPR)
- [ ] IP addresses được mask hoặc anonymize
- [ ] DTOs có @JsonIgnore cho sensitive fields
- [ ] Custom toString() mask sensitive data
- [ ] Logback config có masking patterns
- [ ] Request logging filter mask Authorization header
- [ ] Exception messages không chứa sensitive data

---

## 08.05 - Spring Boot Actuator endpoints cho health/metrics

### Metadata
- **ID:** `08.05`
- **Mức độ:** 🟠 KHUYẾN NGHỊ
- **Lý do:** Monitoring, health checks, operational insights

### Tại sao?

**Vấn đề khi không có Actuator:**
- Không biết app có healthy không
- Không có metrics cho monitoring
- Khó troubleshoot production issues
- Manual health checks qua logs

**Lợi ích Actuator:**
- Health checks cho Kubernetes/AWS
- Prometheus metrics tự động
- Runtime configuration management
- JVM metrics, thread dumps, heap dumps

### ✅ Cách đúng

**Dependencies:**
```xml
<dependencies>
  <!-- Spring Boot Actuator -->
  <dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-actuator</artifactId>
  </dependency>

  <!-- Micrometer Prometheus registry -->
  <dependency>
    <groupId>io.micrometer</groupId>
    <artifactId>micrometer-registry-prometheus</artifactId>
  </dependency>
</dependencies>
```

**Configuration:**
```yaml
# application.yml
management:
  endpoints:
    web:
      exposure:
        # Expose health, info, metrics, prometheus
        include: health,info,metrics,prometheus
      base-path: /actuator

  endpoint:
    health:
      show-details: when-authorized # Chỉ show details khi authenticated
      show-components: when-authorized
      probes:
        enabled: true # Enable liveness/readiness probes

  health:
    livenessState:
      enabled: true
    readinessState:
      enabled: true

  metrics:
    export:
      prometheus:
        enabled: true
    tags:
      application: ${spring.application.name}
      environment: ${spring.profiles.active}

  info:
    env:
      enabled: true
    java:
      enabled: true
    os:
      enabled: true

# Application info
info:
  app:
    name: @project.name@
    version: @project.version@
    description: @project.description@
  build:
    time: @maven.build.timestamp@
```

**Security configuration:**
```java
import org.springframework.boot.actuate.autoconfigure.security.servlet.EndpointRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class ActuatorSecurityConfig {

  @Bean
  public SecurityFilterChain actuatorSecurityFilterChain(HttpSecurity http) throws Exception {
    http
      .securityMatcher(EndpointRequest.toAnyEndpoint())
      .authorizeHttpRequests(authorize -> authorize
        // Public health endpoint (cho load balancer)
        .requestMatchers(EndpointRequest.to("health", "info")).permitAll()

        // Liveness/readiness probes (cho Kubernetes)
        .requestMatchers(EndpointRequest.to("health/liveness")).permitAll()
        .requestMatchers(EndpointRequest.to("health/readiness")).permitAll()

        // Prometheus metrics (restrict by IP or require auth)
        .requestMatchers(EndpointRequest.to("prometheus")).hasRole("ACTUATOR")

        // Other endpoints require ADMIN
        .anyRequest().hasRole("ADMIN")
      );

    return http.build();
  }
}
```

**Custom info contributor:**
```java
import org.springframework.boot.actuate.info.Info;
import org.springframework.boot.actuate.info.InfoContributor;
import org.springframework.stereotype.Component;
import java.time.Instant;
import java.util.Map;

@Component
public class CustomInfoContributor implements InfoContributor {
  private final Instant startTime = Instant.now();

  @Override
  public void contribute(Info.Builder builder) {
    builder.withDetail("app", Map.of(
      "startTime", startTime,
      "uptime", Duration.between(startTime, Instant.now()).toSeconds() + "s"
    ));

    builder.withDetail("database", Map.of(
      "type", "PostgreSQL",
      "version", "15.2"
    ));
  }
}
```

**Kubernetes liveness/readiness probes:**
```yaml
# deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: jr-medicalbox-api
spec:
  template:
    spec:
      containers:
      - name: app
        image: jr-medicalbox-api:latest
        ports:
        - containerPort: 8080

        # Liveness probe: App có alive không?
        livenessProbe:
          httpGet:
            path: /actuator/health/liveness
            port: 8080
          initialDelaySeconds: 30
          periodSeconds: 10
          timeoutSeconds: 5
          failureThreshold: 3

        # Readiness probe: App có ready nhận traffic không?
        readinessProbe:
          httpGet:
            path: /actuator/health/readiness
            port: 8080
          initialDelaySeconds: 10
          periodSeconds: 5
          timeoutSeconds: 3
          failureThreshold: 3
```

**Prometheus scraping config:**
```yaml
# prometheus.yml
scrape_configs:
  - job_name: 'spring-boot-apps'
    metrics_path: '/actuator/prometheus'
    static_configs:
      - targets: ['localhost:8080']
        labels:
          application: 'jr-medicalbox-api'
          environment: 'production'
```

**Available endpoints:**
```bash
# Health check
GET /actuator/health
{
  "status": "UP",
  "groups": ["liveness", "readiness"]
}

# Health details (authenticated)
GET /actuator/health
{
  "status": "UP",
  "components": {
    "db": {"status": "UP"},
    "redis": {"status": "UP"},
    "diskSpace": {"status": "UP"}
  }
}

# Liveness probe
GET /actuator/health/liveness
{"status": "UP"}

# Readiness probe
GET /actuator/health/readiness
{"status": "UP"}

# Application info
GET /actuator/info
{
  "app": {
    "name": "jr-medicalbox-api",
    "version": "1.0.0"
  },
  "build": {
    "time": "2026-02-16T10:30:00Z"
  }
}

# Prometheus metrics
GET /actuator/prometheus
# HELP jvm_memory_used_bytes The amount of used memory
# TYPE jvm_memory_used_bytes gauge
jvm_memory_used_bytes{area="heap",id="PS Eden Space",} 1.2345E8

# All metrics (JSON)
GET /actuator/metrics
{
  "names": [
    "jvm.memory.used",
    "http.server.requests",
    "system.cpu.usage"
  ]
}

# Specific metric
GET /actuator/metrics/http.server.requests
{
  "name": "http.server.requests",
  "measurements": [
    {"statistic": "COUNT", "value": 1523}
  ]
}
```

### ❌ Cách sai

```yaml
# ❌ Expose tất cả endpoints publicly
management:
  endpoints:
    web:
      exposure:
        include: "*" # Security risk!
  endpoint:
    health:
      show-details: always # Leak internal info!

# ❌ Không có security cho actuator
# → Anyone có thể shutdown app via /actuator/shutdown

# ❌ Không enable probes cho Kubernetes
management:
  health:
    livenessState:
      enabled: false # Kubernetes không health check được!
```

### Phát hiện (ripgrep)

```bash
# Kiểm tra actuator dependency
rg "spring-boot-starter-actuator" pom.xml

# Kiểm tra exposure config
rg "management.endpoints.web.exposure" src/main/resources/

# Kiểm tra security config cho actuator
rg "EndpointRequest" --type java
```

### Checklist

- [ ] Dependency `spring-boot-starter-actuator` có trong pom.xml
- [ ] Health endpoint exposed: `/actuator/health`
- [ ] Liveness/readiness probes enabled
- [ ] Prometheus metrics exposed: `/actuator/prometheus`
- [ ] Security config restrict sensitive endpoints
- [ ] Health details chỉ show khi authenticated
- [ ] Kubernetes probes config trong deployment.yaml
- [ ] Info endpoint có app version, build time

---

## 08.06 - Custom health indicators cho external dependencies

### Metadata
- **ID:** `08.06`
- **Mức độ:** 🟡 NÊN CÓ
- **Lý do:** Detect khi external services down trước khi users report

### Tại sao?

**Vấn đề khi không có custom health indicators:**
- App "UP" nhưng không connect được DB
- Redis down → app chậm/crash
- External API down → features không work
- Kubernetes restart app dù app code vẫn OK

**Lợi ích custom health indicators:**
- Early detection của infrastructure issues
- Readiness probe fail → không route traffic
- Automatic health checks cho dependencies
- Better observability

### ✅ Cách đúng

**Database health indicator:**
```java
import org.springframework.boot.actuate.health.Health;
import org.springframework.boot.actuate.health.HealthIndicator;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;

@Component("database")
public class DatabaseHealthIndicator implements HealthIndicator {
  private final JdbcTemplate jdbcTemplate;

  public DatabaseHealthIndicator(JdbcTemplate jdbcTemplate) {
    this.jdbcTemplate = jdbcTemplate;
  }

  @Override
  public Health health() {
    try {
      // Test query
      Long result = jdbcTemplate.queryForObject("SELECT 1", Long.class);

      if (result != null && result == 1) {
        return Health.up()
          .withDetail("database", "PostgreSQL")
          .withDetail("status", "reachable")
          .build();
      } else {
        return Health.down()
          .withDetail("error", "Unexpected query result")
          .build();
      }
    } catch (Exception e) {
      return Health.down()
        .withDetail("error", e.getMessage())
        .withException(e)
        .build();
    }
  }
}
```

**Redis health indicator:**
```java
import org.springframework.boot.actuate.health.Health;
import org.springframework.boot.actuate.health.HealthIndicator;
import org.springframework.data.redis.connection.RedisConnection;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.stereotype.Component;

@Component("redis")
public class RedisHealthIndicator implements HealthIndicator {
  private final RedisConnectionFactory connectionFactory;

  public RedisHealthIndicator(RedisConnectionFactory connectionFactory) {
    this.connectionFactory = connectionFactory;
  }

  @Override
  public Health health() {
    try (RedisConnection connection = connectionFactory.getConnection()) {
      String pong = connection.ping();

      if ("PONG".equals(pong)) {
        return Health.up()
          .withDetail("redis", "available")
          .withDetail("response", pong)
          .build();
      } else {
        return Health.down()
          .withDetail("error", "Unexpected ping response: " + pong)
          .build();
      }
    } catch (Exception e) {
      return Health.down()
        .withDetail("error", e.getMessage())
        .withException(e)
        .build();
    }
  }
}
```

**External API health indicator:**
```java
import org.springframework.boot.actuate.health.Health;
import org.springframework.boot.actuate.health.HealthIndicator;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;
import java.time.Duration;

@Component("paymentGateway")
public class PaymentGatewayHealthIndicator implements HealthIndicator {
  private final RestClient restClient;
  private final String healthCheckUrl;

  public PaymentGatewayHealthIndicator(RestClient.Builder restClientBuilder) {
    this.restClient = restClientBuilder
      .baseUrl("https://payment-gateway.example.com")
      .build();
    this.healthCheckUrl = "/health";
  }

  @Override
  public Health health() {
    try {
      long startTime = System.currentTimeMillis();

      String response = restClient.get()
        .uri(healthCheckUrl)
        .retrieve()
        .body(String.class);

      long responseTime = System.currentTimeMillis() - startTime;

      return Health.up()
        .withDetail("gateway", "Payment Gateway")
        .withDetail("responseTime", responseTime + "ms")
        .withDetail("status", response)
        .build();
    } catch (Exception e) {
      return Health.down()
        .withDetail("gateway", "Payment Gateway")
        .withDetail("error", e.getMessage())
        .withException(e)
        .build();
    }
  }
}
```

**Reactive health indicator (async):**
```java
import org.springframework.boot.actuate.health.Health;
import org.springframework.boot.actuate.health.ReactiveHealthIndicator;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;
import java.time.Duration;

@Component("externalService")
public class ExternalServiceHealthIndicator implements ReactiveHealthIndicator {
  private final WebClient webClient;

  public ExternalServiceHealthIndicator(WebClient.Builder webClientBuilder) {
    this.webClient = webClientBuilder
      .baseUrl("https://api.external-service.com")
      .build();
  }

  @Override
  public Mono<Health> health() {
    return webClient.get()
      .uri("/ping")
      .retrieve()
      .bodyToMono(String.class)
      .timeout(Duration.ofSeconds(5))
      .map(response -> Health.up()
        .withDetail("service", "External API")
        .withDetail("response", response)
        .build())
      .onErrorResume(ex -> Mono.just(Health.down()
        .withDetail("service", "External API")
        .withDetail("error", ex.getMessage())
        .withException(ex)
        .build()));
  }
}
```

**Disk space health indicator:**
```java
import org.springframework.boot.actuate.health.Health;
import org.springframework.boot.actuate.health.HealthIndicator;
import org.springframework.stereotype.Component;
import java.io.File;

@Component("diskSpace")
public class DiskSpaceHealthIndicator implements HealthIndicator {
  private static final long THRESHOLD_BYTES = 10 * 1024 * 1024 * 1024L; // 10GB

  @Override
  public Health health() {
    File root = new File("/");
    long freeSpace = root.getFreeSpace();
    long totalSpace = root.getTotalSpace();
    long usedSpace = totalSpace - freeSpace;

    double usedPercentage = (double) usedSpace / totalSpace * 100;

    if (freeSpace < THRESHOLD_BYTES) {
      return Health.down()
        .withDetail("free", formatBytes(freeSpace))
        .withDetail("total", formatBytes(totalSpace))
        .withDetail("used", String.format("%.2f%%", usedPercentage))
        .withDetail("threshold", formatBytes(THRESHOLD_BYTES))
        .build();
    }

    return Health.up()
      .withDetail("free", formatBytes(freeSpace))
      .withDetail("total", formatBytes(totalSpace))
      .withDetail("used", String.format("%.2f%%", usedPercentage))
      .build();
  }

  private String formatBytes(long bytes) {
    if (bytes < 1024) return bytes + " B";
    int exp = (int) (Math.log(bytes) / Math.log(1024));
    char pre = "KMGTPE".charAt(exp - 1);
    return String.format("%.2f %sB", bytes / Math.pow(1024, exp), pre);
  }
}
```

**Health indicator groups:**
```yaml
# application.yml
management:
  endpoint:
    health:
      group:
        # Liveness group: App process có alive không?
        liveness:
          include: livenessState

        # Readiness group: App có ready nhận traffic không?
        readiness:
          include: readinessState,db,redis

        # Custom group: External dependencies
        external:
          include: paymentGateway,externalService
```

**Response examples:**
```bash
# All health indicators
GET /actuator/health
{
  "status": "UP",
  "components": {
    "db": {"status": "UP"},
    "redis": {"status": "UP"},
    "paymentGateway": {"status": "UP"},
    "diskSpace": {"status": "UP"}
  }
}

# Readiness probe (DB + Redis must be UP)
GET /actuator/health/readiness
{
  "status": "UP",
  "components": {
    "db": {"status": "UP", "details": {"database": "PostgreSQL"}},
    "redis": {"status": "UP", "details": {"response": "PONG"}}
  }
}

# External dependencies
GET /actuator/health/external
{
  "status": "DOWN",
  "components": {
    "paymentGateway": {
      "status": "DOWN",
      "details": {
        "error": "Connection timeout"
      }
    }
  }
}
```

### ❌ Cách sai

```java
// ❌ Blocking I/O trong health check (làm chậm readiness probe)
@Override
public Health health() {
  Thread.sleep(5000); // BAD!
  return Health.up().build();
}

// ❌ Không handle exceptions
@Override
public Health health() {
  jdbcTemplate.queryForObject("SELECT 1", Long.class); // Throws exception!
  return Health.up().build(); // Never reached
}

// ❌ Quá nhiều details (leak internal info)
return Health.down()
  .withDetail("password", dbPassword) // Security leak!
  .withDetail("stackTrace", stackTrace) // Too verbose
  .build();

// ❌ Không set timeout cho external calls
webClient.get().uri("/health").retrieve().block(); // Hang forever!
```

### Phát hiện (ripgrep)

```bash
# Tìm custom health indicators
rg "implements.*HealthIndicator" --type java

# Kiểm tra health groups config
rg "management.endpoint.health.group" src/main/resources/

# Tìm blocking calls trong health checks
rg "Thread\.sleep|\.block\(\)" --type java | rg "HealthIndicator"
```

### Checklist

- [ ] Custom health indicators cho DB, Redis, external APIs
- [ ] Timeout config cho external health checks (< 5s)
- [ ] Exception handling trong mọi health indicators
- [ ] Health groups: liveness, readiness, external
- [ ] Readiness group include critical dependencies (DB, cache)
- [ ] Liveness group chỉ check app process
- [ ] Health details không leak sensitive data
- [ ] Non-blocking health checks (reactive preferred)

---

## 08.07 - Micrometer metrics cho business KPIs

### Metadata
- **ID:** `08.07`
- **Mức độ:** 🟡 NÊN CÓ
- **Lý do:** Track business metrics, identify trends, detect anomalies

### Tại sao?

**Vấn đề khi chỉ có technical metrics:**
- Biết JVM memory usage nhưng không biết business impact
- Không track được user behavior
- Không measure được feature adoption
- Khó identify revenue-impacting issues

**Lợi ích business metrics:**
- Track order conversion rate, cart abandonment
- Measure API endpoint usage per feature
- Detect payment failure trends
- Monitor user engagement

### ✅ Cách đúng

**Counter - Đếm events:**
```java
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import org.springframework.stereotype.Service;

@Service
public class OrderService {
  private final Counter orderCreatedCounter;
  private final Counter orderFailedCounter;
  private final MeterRegistry meterRegistry;

  public OrderService(MeterRegistry meterRegistry) {
    this.meterRegistry = meterRegistry;

    // Counter: Số orders created
    this.orderCreatedCounter = Counter.builder("orders.created")
      .description("Total number of orders created")
      .tag("source", "web")
      .register(meterRegistry);

    // Counter: Số orders failed
    this.orderFailedCounter = Counter.builder("orders.failed")
      .description("Total number of failed orders")
      .register(meterRegistry);
  }

  public Order createOrder(CreateOrderRequest request) {
    try {
      Order order = orderRepository.save(toEntity(request));

      // Increment counter với tags
      orderCreatedCounter.increment();

      meterRegistry.counter("orders.created.by.customer",
        "customerId", request.customerId().toString(),
        "paymentMethod", request.paymentMethod()
      ).increment();

      return order;
    } catch (Exception e) {
      orderFailedCounter.increment();
      throw e;
    }
  }
}
```

**Timer - Đo latency:**
```java
import io.micrometer.core.instrument.Timer;
import org.springframework.stereotype.Service;

@Service
public class PaymentService {
  private final Timer paymentTimer;
  private final MeterRegistry meterRegistry;

  public PaymentService(MeterRegistry meterRegistry) {
    this.meterRegistry = meterRegistry;

    this.paymentTimer = Timer.builder("payment.processing.time")
      .description("Time taken to process payment")
      .publishPercentiles(0.5, 0.95, 0.99) // p50, p95, p99
      .register(meterRegistry);
  }

  public Payment processPayment(PaymentRequest request) {
    // Cách 1: Manual timer
    Timer.Sample sample = Timer.start(meterRegistry);
    try {
      Payment result = paymentGateway.charge(request);

      sample.stop(Timer.builder("payment.processing.time")
        .tag("status", "success")
        .tag("gateway", request.gateway())
        .register(meterRegistry));

      return result;
    } catch (Exception e) {
      sample.stop(Timer.builder("payment.processing.time")
        .tag("status", "failure")
        .tag("gateway", request.gateway())
        .register(meterRegistry));
      throw e;
    }
  }

  // Cách 2: Timed annotation
  @Timed(value = "payment.processing.time", percentiles = {0.5, 0.95, 0.99})
  public Payment processPaymentV2(PaymentRequest request) {
    return paymentGateway.charge(request);
  }
}
```

**Gauge - Track current value:**
```java
import io.micrometer.core.instrument.Gauge;
import org.springframework.stereotype.Service;
import java.util.concurrent.atomic.AtomicInteger;

@Service
public class ConnectionPoolMetrics {
  private final AtomicInteger activeConnections = new AtomicInteger(0);

  public ConnectionPoolMetrics(MeterRegistry meterRegistry) {
    // Gauge: Số connections đang active
    Gauge.builder("db.connections.active", activeConnections, AtomicInteger::get)
      .description("Number of active database connections")
      .register(meterRegistry);

    // Gauge từ lambda
    Gauge.builder("db.connections.idle", () -> getIdleConnectionCount())
      .description("Number of idle database connections")
      .register(meterRegistry);
  }

  public void acquireConnection() {
    activeConnections.incrementAndGet();
  }

  public void releaseConnection() {
    activeConnections.decrementAndGet();
  }

  private int getIdleConnectionCount() {
    // Logic to get idle connections
    return 10;
  }
}
```

**Distribution Summary - Track distribution:**
```java
import io.micrometer.core.instrument.DistributionSummary;
import org.springframework.stereotype.Service;

@Service
public class CartService {
  private final DistributionSummary cartSizeSummary;

  public CartService(MeterRegistry meterRegistry) {
    this.cartSizeSummary = DistributionSummary.builder("cart.items.count")
      .description("Number of items in cart")
      .baseUnit("items")
      .publishPercentiles(0.5, 0.95, 0.99)
      .register(meterRegistry);
  }

  public Cart checkout(Long cartId) {
    Cart cart = cartRepository.findById(cartId).orElseThrow();

    // Record cart size distribution
    cartSizeSummary.record(cart.getItems().size());

    // Record cart total amount
    DistributionSummary.builder("cart.total.amount")
      .baseUnit("JPY")
      .tag("customerId", cart.getCustomerId().toString())
      .register(meterRegistry)
      .record(cart.getTotalAmount().doubleValue());

    return cart;
  }
}
```

**Custom metrics với MeterBinder:**
```java
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.binder.MeterBinder;
import org.springframework.stereotype.Component;

@Component
public class BusinessMetrics implements MeterBinder {
  private final OrderRepository orderRepository;

  public BusinessMetrics(OrderRepository orderRepository) {
    this.orderRepository = orderRepository;
  }

  @Override
  public void bindTo(MeterRegistry registry) {
    // Gauge: Total pending orders
    Gauge.builder("orders.pending.count", orderRepository, repo ->
        repo.countByStatus(OrderStatus.PENDING)
      )
      .description("Number of pending orders")
      .register(registry);

    // Gauge: Today's revenue
    Gauge.builder("revenue.today", this, metrics ->
        orderRepository.getTodayRevenue().doubleValue()
      )
      .description("Total revenue today")
      .baseUnit("JPY")
      .register(registry);
  }
}
```

**Aspect-based metrics:**
```java
import io.micrometer.core.annotation.Timed;
import io.micrometer.core.annotation.Counted;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.springframework.stereotype.Component;

@Aspect
@Component
public class MetricsAspect {
  private final MeterRegistry meterRegistry;

  public MetricsAspect(MeterRegistry meterRegistry) {
    this.meterRegistry = meterRegistry;
  }

  @Around("@annotation(TrackApiCall)")
  public Object trackApiCall(ProceedingJoinPoint joinPoint) throws Throwable {
    String methodName = joinPoint.getSignature().getName();

    Timer.Sample sample = Timer.start(meterRegistry);
    try {
      Object result = joinPoint.proceed();

      sample.stop(Timer.builder("api.call.duration")
        .tag("method", methodName)
        .tag("status", "success")
        .register(meterRegistry));

      meterRegistry.counter("api.call.count",
        "method", methodName,
        "status", "success"
      ).increment();

      return result;
    } catch (Exception e) {
      sample.stop(Timer.builder("api.call.duration")
        .tag("method", methodName)
        .tag("status", "failure")
        .register(meterRegistry));

      meterRegistry.counter("api.call.count",
        "method", methodName,
        "status", "failure",
        "exception", e.getClass().getSimpleName()
      ).increment();

      throw e;
    }
  }
}

// Usage
@Service
public class UserService {
  @TrackApiCall
  public User getUser(Long userId) {
    return userRepository.findById(userId).orElseThrow();
  }
}
```

**Prometheus query examples:**
```promql
# Request rate per endpoint
rate(http_server_requests_seconds_count{uri="/api/orders"}[5m])

# p95 latency
histogram_quantile(0.95,
  rate(http_server_requests_seconds_bucket[5m])
)

# Error rate
rate(http_server_requests_seconds_count{status="500"}[5m]) /
rate(http_server_requests_seconds_count[5m])

# Order creation trend
increase(orders_created_total[1h])

# Payment success rate
sum(rate(payment_processing_time_seconds_count{status="success"}[5m])) /
sum(rate(payment_processing_time_seconds_count[5m]))
```

**Grafana dashboard config:**
```yaml
# grafana-dashboard.json
{
  "dashboard": {
    "title": "Medical Box API - Business Metrics",
    "panels": [
      {
        "title": "Order Creation Rate",
        "targets": [{
          "expr": "rate(orders_created_total[5m])"
        }]
      },
      {
        "title": "Payment Success Rate",
        "targets": [{
          "expr": "sum(rate(payment_processing_time_seconds_count{status=\"success\"}[5m])) / sum(rate(payment_processing_time_seconds_count[5m]))"
        }]
      },
      {
        "title": "API Latency (p95)",
        "targets": [{
          "expr": "histogram_quantile(0.95, rate(http_server_requests_seconds_bucket[5m]))"
        }]
      }
    ]
  }
}
```

### ❌ Cách sai

```java
// ❌ Quá nhiều unique tags (cardinality explosion)
counter.increment(
  "userId", userId.toString(), // BAD: millions of unique values!
  "timestamp", Instant.now().toString()
);

// ❌ Tạo mới metrics trong loop
for (Order order : orders) {
  Counter.builder("order.processed") // Memory leak!
    .tag("orderId", order.getId().toString())
    .register(meterRegistry)
    .increment();
}

// ❌ Không có description/baseUnit
Counter.builder("cnt").register(meterRegistry); // Unclear metric

// ❌ Timer không có percentiles
Timer.builder("slow.operation")
  .register(meterRegistry); // Không track p95, p99
```

### Phát hiện (ripgrep)

```bash
# Kiểm tra có MeterRegistry injections
rg "MeterRegistry" --type java

# Tìm @Timed annotations
rg "@Timed" --type java

# Kiểm tra metrics naming convention
rg "Counter\.builder\(\"[A-Z]" --type java # Should be lowercase

# Tìm potential cardinality issues
rg "\.tag\(\".*Id\"|\.tag\(\"timestamp" --type java
```

### Checklist

- [ ] Counter cho business events (orders, payments, logins)
- [ ] Timer cho critical operations (payment, API calls)
- [ ] Gauge cho current state (connections, queue size)
- [ ] DistributionSummary cho value distributions (cart size, amount)
- [ ] Metrics có description và baseUnit
- [ ] Tags có low cardinality (< 100 unique values)
- [ ] Timer có percentiles (p50, p95, p99)
- [ ] Prometheus queries documented
- [ ] Grafana dashboards created

---

## 08.08 - Log rotation và retention policy

### Metadata
- **ID:** `08.08`
- **Mức độ:** 🟠 KHUYẾN NGHỊ
- **Lý do:** Tránh disk full, comply với data retention regulations

### Tại sao?

**Vấn đề khi không có log rotation:**
- Disk full → app crash
- Logs chiếm hàng trăm GB
- Vi phạm GDPR (log personal data > 30 days)
- Khó search trong log files khổng lồ

**Lợi ích log rotation:**
- Giới hạn disk usage
- Archive old logs
- Faster log search
- Compliance với regulations

### ✅ Cách đúng

**Logback rolling policy:**
```xml
<configuration>
  <property name="LOG_PATH" value="logs"/>
  <property name="APP_NAME" value="jr-medicalbox-api"/>

  <!-- Console appender -->
  <appender name="CONSOLE" class="ch.qos.logback.core.ConsoleAppender">
    <encoder class="net.logstash.logback.encoder.LogstashEncoder"/>
  </appender>

  <!-- File appender với size and time based rolling -->
  <appender name="FILE" class="ch.qos.logback.core.rolling.RollingFileAppender">
    <file>${LOG_PATH}/${APP_NAME}.json</file>

    <!-- Rolling policy: size + time -->
    <rollingPolicy class="ch.qos.logback.core.rolling.SizeAndTimeBasedRollingPolicy">
      <!-- Daily rollover -->
      <fileNamePattern>${LOG_PATH}/archive/${APP_NAME}-%d{yyyy-MM-dd}.%i.json.gz</fileNamePattern>

      <!-- Mỗi file max 100MB -->
      <maxFileSize>100MB</maxFileSize>

      <!-- Giữ logs trong 30 ngày -->
      <maxHistory>30</maxHistory>

      <!-- Tổng size max 10GB -->
      <totalSizeCap>10GB</totalSizeCap>

      <!-- Cleanup khi start app -->
      <cleanHistoryOnStart>true</cleanHistoryOnStart>
    </rollingPolicy>

    <encoder class="net.logstash.logback.encoder.LogstashEncoder">
      <includeMdcKeyNames>requestId,userId,sessionId</includeMdcKeyNames>
    </encoder>
  </appender>

  <!-- Separate ERROR log file -->
  <appender name="ERROR_FILE" class="ch.qos.logback.core.rolling.RollingFileAppender">
    <file>${LOG_PATH}/${APP_NAME}-error.json</file>

    <filter class="ch.qos.logback.classic.filter.ThresholdFilter">
      <level>ERROR</level>
    </filter>

    <rollingPolicy class="ch.qos.logback.core.rolling.SizeAndTimeBasedRollingPolicy">
      <fileNamePattern>${LOG_PATH}/archive/${APP_NAME}-error-%d{yyyy-MM-dd}.%i.json.gz</fileNamePattern>
      <maxFileSize>50MB</maxFileSize>
      <maxHistory>90</maxHistory> <!-- Errors giữ lâu hơn -->
      <totalSizeCap>5GB</totalSizeCap>
    </rollingPolicy>

    <encoder class="net.logstash.logback.encoder.LogstashEncoder"/>
  </appender>

  <!-- Async appenders (better performance) -->
  <appender name="ASYNC_FILE" class="ch.qos.logback.classic.AsyncAppender">
    <appender-ref ref="FILE"/>
    <queueSize>512</queueSize>
    <discardingThreshold>0</discardingThreshold>
    <neverBlock>false</neverBlock>
  </appender>

  <appender name="ASYNC_ERROR_FILE" class="ch.qos.logback.classic.AsyncAppender">
    <appender-ref ref="ERROR_FILE"/>
    <queueSize>256</queueSize>
  </appender>

  <root level="INFO">
    <appender-ref ref="CONSOLE"/>
    <appender-ref ref="ASYNC_FILE"/>
    <appender-ref ref="ASYNC_ERROR_FILE"/>
  </root>
</configuration>
```

**Environment-specific retention:**
```xml
<!-- logback-spring.xml -->
<configuration>
  <!-- Development: Short retention -->
  <springProfile name="dev">
    <appender name="FILE" class="ch.qos.logback.core.rolling.RollingFileAppender">
      <rollingPolicy class="ch.qos.logback.core.rolling.SizeAndTimeBasedRollingPolicy">
        <fileNamePattern>logs/dev-%d{yyyy-MM-dd}.%i.json</fileNamePattern>
        <maxFileSize>50MB</maxFileSize>
        <maxHistory>7</maxHistory> <!-- 7 days -->
        <totalSizeCap>1GB</totalSizeCap>
      </rollingPolicy>
    </appender>
  </springProfile>

  <!-- Production: Long retention + compression -->
  <springProfile name="prod">
    <appender name="FILE" class="ch.qos.logback.core.rolling.RollingFileAppender">
      <rollingPolicy class="ch.qos.logback.core.rolling.SizeAndTimeBasedRollingPolicy">
        <fileNamePattern>logs/prod-%d{yyyy-MM-dd}.%i.json.gz</fileNamePattern>
        <maxFileSize>100MB</maxFileSize>
        <maxHistory>30</maxHistory> <!-- 30 days -->
        <totalSizeCap>10GB</totalSizeCap>
      </rollingPolicy>
    </appender>
  </springProfile>
</configuration>
```

**Separate appenders per logger:**
```xml
<configuration>
  <!-- Audit log: Long retention, never delete -->
  <appender name="AUDIT_FILE" class="ch.qos.logback.core.rolling.RollingFileAppender">
    <file>logs/audit.json</file>
    <rollingPolicy class="ch.qos.logback.core.rolling.TimeBasedRollingPolicy">
      <fileNamePattern>logs/archive/audit-%d{yyyy-MM-dd}.json.gz</fileNamePattern>
      <maxHistory>365</maxHistory> <!-- 1 year -->
    </rollingPolicy>
    <encoder class="net.logstash.logback.encoder.LogstashEncoder"/>
  </appender>

  <!-- Security log: Medium retention -->
  <appender name="SECURITY_FILE" class="ch.qos.logback.core.rolling.RollingFileAppender">
    <file>logs/security.json</file>
    <rollingPolicy class="ch.qos.logback.core.rolling.SizeAndTimeBasedRollingPolicy">
      <fileNamePattern>logs/archive/security-%d{yyyy-MM-dd}.%i.json.gz</fileNamePattern>
      <maxFileSize>100MB</maxFileSize>
      <maxHistory>90</maxHistory> <!-- 90 days -->
    </rollingPolicy>
    <encoder class="net.logstash.logback.encoder.LogstashEncoder"/>
  </appender>

  <!-- Audit logger -->
  <logger name="jp.medicalbox.audit" level="INFO" additivity="false">
    <appender-ref ref="AUDIT_FILE"/>
  </logger>

  <!-- Security logger -->
  <logger name="jp.medicalbox.security" level="INFO" additivity="false">
    <appender-ref ref="SECURITY_FILE"/>
  </logger>
</configuration>
```

**Cron job để cleanup old logs:**
```bash
#!/bin/bash
# cleanup-logs.sh

LOG_DIR="/var/log/jr-medicalbox-api"
RETENTION_DAYS=30

# Delete logs older than retention period
find "$LOG_DIR" -name "*.log*" -type f -mtime +$RETENTION_DAYS -delete

# Delete compressed logs older than 90 days
find "$LOG_DIR" -name "*.gz" -type f -mtime +90 -delete

# Alert if disk usage > 80%
DISK_USAGE=$(df -h "$LOG_DIR" | awk 'NR==2 {print $5}' | sed 's/%//')
if [ "$DISK_USAGE" -gt 80 ]; then
  echo "WARNING: Log disk usage at ${DISK_USAGE}%" | mail -s "Log Disk Alert" admin@example.com
fi
```

**Logrotate config (Linux):**
```bash
# /etc/logrotate.d/jr-medicalbox-api
/var/log/jr-medicalbox-api/*.log {
  daily
  rotate 30
  compress
  delaycompress
  missingok
  notifempty
  create 0644 app app
  sharedscripts
  postrotate
    # Signal app to reopen log files
    kill -USR1 $(cat /var/run/jr-medicalbox-api.pid) 2>/dev/null || true
  endscript
}
```

**Monitoring disk usage:**
```java
import org.springframework.boot.actuate.health.Health;
import org.springframework.boot.actuate.health.HealthIndicator;
import org.springframework.stereotype.Component;
import java.io.File;

@Component("logDiskSpace")
public class LogDiskSpaceHealthIndicator implements HealthIndicator {
  private static final String LOG_PATH = "logs";
  private static final long THRESHOLD_BYTES = 1024 * 1024 * 1024L; // 1GB free

  @Override
  public Health health() {
    File logDir = new File(LOG_PATH);
    if (!logDir.exists()) {
      return Health.unknown().withDetail("error", "Log directory not found").build();
    }

    long totalSpace = logDir.getTotalSpace();
    long freeSpace = logDir.getFreeSpace();
    long usedSpace = totalSpace - freeSpace;

    long logDirSize = getDirectorySize(logDir);

    if (freeSpace < THRESHOLD_BYTES) {
      return Health.down()
        .withDetail("freeSpace", formatBytes(freeSpace))
        .withDetail("threshold", formatBytes(THRESHOLD_BYTES))
        .withDetail("logDirSize", formatBytes(logDirSize))
        .build();
    }

    return Health.up()
      .withDetail("freeSpace", formatBytes(freeSpace))
      .withDetail("logDirSize", formatBytes(logDirSize))
      .build();
  }

  private long getDirectorySize(File directory) {
    long size = 0;
    File[] files = directory.listFiles();
    if (files != null) {
      for (File file : files) {
        if (file.isFile()) {
          size += file.length();
        } else if (file.isDirectory()) {
          size += getDirectorySize(file);
        }
      }
    }
    return size;
  }

  private String formatBytes(long bytes) {
    if (bytes < 1024) return bytes + " B";
    int exp = (int) (Math.log(bytes) / Math.log(1024));
    char pre = "KMGTPE".charAt(exp - 1);
    return String.format("%.2f %sB", bytes / Math.pow(1024, exp), pre);
  }
}
```

### ❌ Cách sai

```xml
<!-- ❌ Không có maxHistory (logs tích tụ vô hạn) -->
<rollingPolicy class="ch.qos.logback.core.rolling.TimeBasedRollingPolicy">
  <fileNamePattern>logs/app-%d{yyyy-MM-dd}.log</fileNamePattern>
  <!-- Missing maxHistory! -->
</rollingPolicy>

<!-- ❌ Không compress old logs -->
<fileNamePattern>logs/app-%d{yyyy-MM-dd}.log</fileNamePattern> <!-- Should be .log.gz -->

<!-- ❌ Không có totalSizeCap (disk full) -->
<rollingPolicy class="ch.qos.logback.core.rolling.SizeAndTimeBasedRollingPolicy">
  <maxFileSize>100MB</maxFileSize>
  <maxHistory>365</maxHistory>
  <!-- Missing totalSizeCap! 365 * N files = disk full -->
</rollingPolicy>

<!-- ❌ Log files quá lớn (khó open) -->
<maxFileSize>10GB</maxFileSize> <!-- Too large! -->
```

### Phát hiện (ripgrep)

```bash
# Kiểm tra có rolling policy không
rg "RollingFileAppender" src/main/resources/

# Kiểm tra có maxHistory không
rg "maxHistory" src/main/resources/logback*.xml

# Kiểm tra có compression không
rg "fileNamePattern.*\.gz" src/main/resources/

# Kiểm tra có totalSizeCap không
rg "totalSizeCap" src/main/resources/
```

### Checklist

- [ ] RollingFileAppender với SizeAndTimeBasedRollingPolicy
- [ ] maxHistory set (30 days standard, 90 for errors, 365 for audit)
- [ ] maxFileSize ≤ 100MB
- [ ] totalSizeCap configured
- [ ] Compression enabled (.gz extension)
- [ ] Separate ERROR log với longer retention
- [ ] Async appenders cho performance
- [ ] Health indicator monitor disk usage
- [ ] Cron job hoặc logrotate config
- [ ] Different retention per environment (dev: 7 days, prod: 30 days)

---

## 08.09 - Distributed tracing (Micrometer Tracing)

### Metadata
- **ID:** `08.09`
- **Mức độ:** 🟡 NÊN CÓ
- **Lý do:** Debug distributed systems, track requests qua nhiều services

### Tại sao?

**Vấn đề trong microservices:**
- Request đi qua 5+ services
- Không biết service nào slow
- Khó debug cascading failures
- Logs từ nhiều services không correlate được

**Lợi ích distributed tracing:**
- Trace request từ đầu đến cuối
- Visualize service dependencies
- Identify performance bottlenecks
- Correlate logs qua services

### ✅ Cách đúng

**Dependencies (Micrometer Tracing + Zipkin):**
```xml
<dependencies>
  <!-- Micrometer Tracing API -->
  <dependency>
    <groupId>io.micrometer</groupId>
    <artifactId>micrometer-tracing</artifactId>
  </dependency>

  <!-- Micrometer Tracing Bridge for Brave (Zipkin client) -->
  <dependency>
    <groupId>io.micrometer</groupId>
    <artifactId>micrometer-tracing-bridge-brave</artifactId>
  </dependency>

  <!-- Zipkin reporter -->
  <dependency>
    <groupId>io.zipkin.reporter2</groupId>
    <artifactId>zipkin-reporter-brave</artifactId>
  </dependency>

  <!-- Optional: OpenTelemetry alternative -->
  <!--
  <dependency>
    <groupId>io.micrometer</groupId>
    <artifactId>micrometer-tracing-bridge-otel</artifactId>
  </dependency>
  -->
</dependencies>
```

**Configuration:**
```yaml
# application.yml
management:
  tracing:
    sampling:
      probability: 1.0 # 100% sampling (development)
      # probability: 0.1 # 10% sampling (production)

  zipkin:
    tracing:
      endpoint: http://localhost:9411/api/v2/spans

spring:
  application:
    name: jr-medicalbox-api

# Logging: Include trace/span IDs
logging:
  pattern:
    level: "%5p [${spring.application.name:},%X{traceId:-},%X{spanId:-}]"
```

**Production config (lower sampling):**
```yaml
# application-prod.yml
management:
  tracing:
    sampling:
      probability: 0.1 # 10% sampling (giảm overhead)
```

**Manual span creation:**
```java
import io.micrometer.tracing.Span;
import io.micrometer.tracing.Tracer;
import org.springframework.stereotype.Service;

@Service
public class OrderService {
  private final Tracer tracer;
  private final OrderRepository orderRepository;

  public OrderService(Tracer tracer, OrderRepository orderRepository) {
    this.tracer = tracer;
    this.orderRepository = orderRepository;
  }

  public Order createOrder(CreateOrderRequest request) {
    // Create custom span
    Span span = tracer.nextSpan().name("order.create").start();
    try (Tracer.SpanInScope ws = tracer.withSpan(span)) {
      // Add tags
      span.tag("customerId", request.customerId().toString());
      span.tag("itemCount", String.valueOf(request.items().size()));

      Order order = orderRepository.save(toEntity(request));

      // Add event
      span.event("order.saved");

      // Nested span cho validation
      Span validationSpan = tracer.nextSpan().name("order.validate").start();
      try (Tracer.SpanInScope ws2 = tracer.withSpan(validationSpan)) {
        validateOrder(order);
        validationSpan.tag("status", "valid");
      } finally {
        validationSpan.end();
      }

      return order;
    } catch (Exception e) {
      span.error(e);
      throw e;
    } finally {
      span.end();
    }
  }
}
```

**Automatic tracing cho HTTP calls:**
```java
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.client.RestTemplate;

@Configuration
public class RestClientConfig {

  @Bean
  public RestTemplate restTemplate(RestTemplateBuilder builder) {
    // Micrometer Tracing tự động inject trace headers
    return builder.build();
  }
}

// RestClient (Spring 6.1+)
@Configuration
public class RestClientConfig {

  @Bean
  public RestClient restClient(RestClient.Builder builder) {
    // Tự động propagate trace context
    return builder.build();
  }
}
```

**Async operations với tracing:**
```java
import io.micrometer.tracing.Tracer;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import java.util.concurrent.CompletableFuture;

@Service
public class NotificationService {
  private final Tracer tracer;

  public NotificationService(Tracer tracer) {
    this.tracer = tracer;
  }

  @Async
  public CompletableFuture<Void> sendEmailAsync(String recipient, String subject) {
    // Trace context được propagate tự động qua @Async
    Span span = tracer.currentSpan();
    if (span != null) {
      span.tag("recipient", recipient);
      span.tag("subject", subject);
    }

    // Send email...
    return CompletableFuture.completedFuture(null);
  }
}
```

**Database tracing:**
```java
import io.micrometer.tracing.Span;
import io.micrometer.tracing.Tracer;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

@Repository
public class CustomOrderRepository {
  private final JdbcTemplate jdbcTemplate;
  private final Tracer tracer;

  public CustomOrderRepository(JdbcTemplate jdbcTemplate, Tracer tracer) {
    this.jdbcTemplate = jdbcTemplate;
    this.tracer = tracer;
  }

  public List<Order> findExpensiveOrders(BigDecimal minAmount) {
    Span span = tracer.nextSpan().name("db.query.expensive-orders").start();
    try (Tracer.SpanInScope ws = tracer.withSpan(span)) {
      span.tag("db.system", "postgresql");
      span.tag("db.operation", "SELECT");
      span.tag("db.table", "trx_order");

      String sql = "SELECT * FROM trx_order WHERE total_amount >= ? ORDER BY total_amount DESC";

      List<Order> results = jdbcTemplate.query(sql, orderRowMapper, minAmount);

      span.tag("db.rows", String.valueOf(results.size()));
      return results;
    } finally {
      span.end();
    }
  }
}
```

**Baggage propagation (cross-service context):**
```java
import io.micrometer.tracing.Tracer;
import io.micrometer.tracing.BaggageInScope;
import org.springframework.stereotype.Service;

@Service
public class UserService {
  private final Tracer tracer;

  public UserService(Tracer tracer) {
    this.tracer = tracer;
  }

  public User getUser(Long userId) {
    // Put data vào baggage (propagate qua services)
    try (BaggageInScope userIdBaggage = tracer.createBaggage("userId", userId.toString())) {
      // Baggage sẽ được propagate qua HTTP headers
      return userRepository.findById(userId).orElseThrow();
    }
  }
}

// Downstream service có thể access baggage
@Service
public class AuditService {
  private final Tracer tracer;

  public void logAudit(String action) {
    String userId = tracer.getBaggage("userId").get();
    log.info("User {} performed action: {}", userId, action);
  }
}
```

**Docker Compose với Zipkin:**
```yaml
# docker-compose.yml
version: '3.8'
services:
  zipkin:
    image: openzipkin/zipkin:latest
    ports:
      - "9411:9411"
    environment:
      - STORAGE_TYPE=mem

  app:
    build: .
    ports:
      - "8080:8080"
    environment:
      - MANAGEMENT_ZIPKIN_TRACING_ENDPOINT=http://zipkin:9411/api/v2/spans
    depends_on:
      - zipkin
```

**Trace context trong logs:**
```json
{
  "@timestamp": "2026-02-16T10:30:45.123+07:00",
  "message": "Creating order",
  "level": "INFO",
  "traceId": "6e0c63257de34c92bf9efcd03927272e",
  "spanId": "bf9efcd039272720",
  "customerId": 12345,
  "requestId": "abc123"
}
```

**Zipkin UI queries:**
```bash
# Access Zipkin UI
http://localhost:9411/zipkin/

# Search traces
- By service name: jr-medicalbox-api
- By span name: order.create
- By tag: customerId=12345
- By duration: > 1000ms
- By time range: Last 15 minutes
```

**Custom trace filters:**
```java
import io.micrometer.tracing.Span;
import io.micrometer.tracing.Tracer;
import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.stereotype.Component;
import java.io.IOException;

@Component
public class TraceEnrichmentFilter implements Filter {
  private final Tracer tracer;

  public TraceEnrichmentFilter(Tracer tracer) {
    this.tracer = tracer;
  }

  @Override
  public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
      throws IOException, ServletException {
    HttpServletRequest httpRequest = (HttpServletRequest) request;

    Span currentSpan = tracer.currentSpan();
    if (currentSpan != null) {
      // Add custom tags
      currentSpan.tag("http.url", httpRequest.getRequestURI());
      currentSpan.tag("http.method", httpRequest.getMethod());
      currentSpan.tag("user.agent", httpRequest.getHeader("User-Agent"));

      String userId = (String) httpRequest.getAttribute("userId");
      if (userId != null) {
        currentSpan.tag("user.id", userId);
      }
    }

    chain.doFilter(request, response);
  }
}
```

### ❌ Cách sai

```java
// ❌ Không end span (memory leak)
Span span = tracer.nextSpan().start();
// Missing span.end()!

// ❌ Span không trong try-finally
Span span = tracer.nextSpan().start();
doSomething(); // Exception → span không end
span.end();

// ❌ Production có 100% sampling (performance hit)
management:
  tracing:
    sampling:
      probability: 1.0 # Too high for production!

// ❌ Quá nhiều tags (cardinality explosion)
span.tag("userId", userId); // Millions of unique values!
```

### Phát hiện (ripgrep)

```bash
# Kiểm tra micrometer-tracing dependency
rg "micrometer-tracing" pom.xml

# Kiểm tra sampling probability config
rg "management.tracing.sampling" src/main/resources/

# Tìm manual spans không có .end()
rg "nextSpan\(\)\.start\(\)" --type java -A 10 | rg -v "\.end\(\)"

# Kiểm tra Zipkin endpoint config
rg "zipkin.tracing.endpoint" src/main/resources/
```

### Checklist

- [ ] Dependencies: `micrometer-tracing-bridge-brave` + `zipkin-reporter-brave`
- [ ] Sampling probability: 1.0 (dev), 0.1 (prod)
- [ ] Zipkin endpoint configured
- [ ] Logs include traceId và spanId
- [ ] Manual spans có try-finally với span.end()
- [ ] Custom spans có tags (service, operation, customerId)
- [ ] RestTemplate/RestClient tự động propagate trace context
- [ ] Async operations preserve trace context
- [ ] Zipkin UI accessible
- [ ] Production sampling rate ≤ 10%

---

## Summary

Domain 08 Best Practices recap:

| ID | Practice | Mức độ | Trọng số |
|----|----------|--------|----------|
| 08.01 | Structured logging (JSON format) | 🟠 KHUYẾN NGHỊ | ×1 |
| 08.02 | MDC cho request tracing | 🟠 KHUYẾN NGHỊ | ×1 |
| 08.03 | Log levels đúng mục đích | 🟠 KHUYẾN NGHỊ | ×1 |
| 08.04 | Không log sensitive data | 🔴 BẮT BUỘC | ×3 |
| 08.05 | Spring Boot Actuator endpoints | 🟠 KHUYẾN NGHỊ | ×1 |
| 08.06 | Custom health indicators | 🟡 NÊN CÓ | ×0.5 |
| 08.07 | Micrometer metrics cho business KPIs | 🟡 NÊN CÓ | ×0.5 |
| 08.08 | Log rotation và retention policy | 🟠 KHUYẾN NGHỊ | ×1 |
| 08.09 | Distributed tracing | 🟡 NÊN CÓ | ×0.5 |

**Checklist tổng:**
- [ ] JSON logging với Logstash encoder
- [ ] MDC filter inject requestId, userId, sessionId
- [ ] Log levels: ERROR (system failures), WARN (unexpected), INFO (business events), DEBUG (troubleshooting)
- [ ] Sensitive data masking (passwords, tokens, cards)
- [ ] Actuator health/metrics endpoints
- [ ] Custom health indicators cho DB, Redis, external APIs
- [ ] Business metrics (counters, timers, gauges)
- [ ] Log rotation với maxHistory, totalSizeCap, compression
- [ ] Distributed tracing với Micrometer Tracing + Zipkin

