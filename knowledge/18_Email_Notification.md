# Domain 18: Email & Notification
> **Số practices:** 8 | 🔴 2 | 🟠 4 | 🟡 2
> **Trọng số:** ×1

---

## 18.01 | Template engine (Thymeleaf) cho email content | 🟠 KHUYẾN NGHỊ

### Metadata
- **ID:** `EMAIL_TEMPLATE_ENGINE`
- **Mức độ:** 🟠 KHUYẾN NGHỊ
- **Lý do:** Maintainability, internationalization, design consistency

### Tại sao?

**Vấn đề với hardcoded HTML:**
```java
// ❌ Khó maintain, không có i18n, design không nhất quán
String html = "<html><body><h1>Hello " + username + "</h1>" +
              "<p>Your order " + orderId + " has been confirmed.</p>" +
              "</body></html>";
```

**Lợi ích của template engine:**
- ✅ Tách logic và presentation
- ✅ Hỗ trợ i18n tự động
- ✅ Designer có thể chỉnh sửa template
- ✅ Dễ test và preview
- ✅ Tái sử dụng layout và component

### ✅ Cách đúng

**1. Configuration:**
```java
@Configuration
public class EmailTemplateConfig {

  @Bean
  public SpringTemplateEngine emailTemplateEngine() {
    SpringTemplateEngine templateEngine = new SpringTemplateEngine();
    templateEngine.addTemplateResolver(emailTemplateResolver());
    return templateEngine;
  }

  @Bean
  public ITemplateResolver emailTemplateResolver() {
    ClassLoaderTemplateResolver resolver = new ClassLoaderTemplateResolver();
    resolver.setPrefix("templates/email/");
    resolver.setSuffix(".html");
    resolver.setTemplateMode(TemplateMode.HTML);
    resolver.setCharacterEncoding("UTF-8");
    resolver.setCacheable(true);
    resolver.setCacheTTLMs(3600000L); // 1 hour
    return resolver;
  }
}
```

**2. Email template (resources/templates/email/order-confirmation.html):**
```html
<!DOCTYPE html>
<html xmlns:th="http://www.thymeleaf.org">
<head>
  <meta charset="UTF-8">
  <title th:text="#{email.order.title}">Order Confirmation</title>
  <style>
    body { font-family: Arial, sans-serif; }
    .header { background: #007bff; color: white; padding: 20px; }
    .content { padding: 20px; }
    .footer { background: #f8f9fa; padding: 10px; text-align: center; }
  </style>
</head>
<body>
  <div class="header">
    <h1 th:text="#{email.order.header}">Order Confirmation</h1>
  </div>

  <div class="content">
    <p th:text="#{email.order.greeting(${customerName})}">Hello Customer,</p>

    <p th:text="#{email.order.message(${orderId})}">
      Your order #12345 has been confirmed.
    </p>

    <table border="1" cellpadding="10">
      <thead>
        <tr>
          <th th:text="#{email.order.product}">Product</th>
          <th th:text="#{email.order.quantity}">Quantity</th>
          <th th:text="#{email.order.price}">Price</th>
        </tr>
      </thead>
      <tbody>
        <tr th:each="item : ${orderItems}">
          <td th:text="${item.productName}">Product A</td>
          <td th:text="${item.quantity}">1</td>
          <td th:text="${#numbers.formatCurrency(item.price)}">$100.00</td>
        </tr>
      </tbody>
    </table>

    <p>
      <strong th:text="#{email.order.total}">Total:</strong>
      <span th:text="${#numbers.formatCurrency(totalAmount)}">$100.00</span>
    </p>

    <p>
      <a th:href="@{${trackingUrl}}" th:text="#{email.order.track}">
        Track your order
      </a>
    </p>
  </div>

  <div class="footer">
    <p th:text="#{email.footer.copyright}">© 2024 Company. All rights reserved.</p>
    <p>
      <a th:href="@{${unsubscribeUrl}}" th:text="#{email.footer.unsubscribe}">
        Unsubscribe
      </a>
    </p>
  </div>
</body>
</html>
```

**3. Email service:**
```java
@Service
@RequiredArgsConstructor
public class EmailService {

  private final JavaMailSender mailSender;
  private final SpringTemplateEngine templateEngine;
  private final MessageSource messageSource;

  public void sendOrderConfirmation(Order order) {
    Context context = new Context(order.getCustomer().getLocale());
    context.setVariable("customerName", order.getCustomer().getName());
    context.setVariable("orderId", order.getId());
    context.setVariable("orderItems", order.getItems());
    context.setVariable("totalAmount", order.getTotalAmount());
    context.setVariable("trackingUrl", buildTrackingUrl(order));
    context.setVariable("unsubscribeUrl", buildUnsubscribeUrl(order.getCustomer()));

    String htmlContent = templateEngine.process("order-confirmation", context);

    sendEmail(
      order.getCustomer().getEmail(),
      messageSource.getMessage("email.order.subject",
        new Object[]{order.getId()},
        order.getCustomer().getLocale()),
      htmlContent
    );
  }

  private void sendEmail(String to, String subject, String htmlContent) {
    MimeMessage message = mailSender.createMimeMessage();
    try {
      MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");
      helper.setTo(to);
      helper.setSubject(subject);
      helper.setText(htmlContent, true); // true = HTML
      helper.setFrom("noreply@example.com");

      mailSender.send(message);
    } catch (MessagingException e) {
      throw new EmailSendException("Failed to send email", e);
    }
  }

  private String buildTrackingUrl(Order order) {
    return "https://example.com/orders/" + order.getId() + "/track";
  }

  private String buildUnsubscribeUrl(Customer customer) {
    return "https://example.com/unsubscribe?token=" + customer.getUnsubscribeToken();
  }
}
```

**4. Messages properties (messages_vi.properties):**
```properties
email.order.title=Xác nhận đơn hàng
email.order.header=Xác nhận đơn hàng
email.order.greeting=Xin chào {0},
email.order.message=Đơn hàng #{0} của bạn đã được xác nhận.
email.order.product=Sản phẩm
email.order.quantity=Số lượng
email.order.price=Giá
email.order.total=Tổng cộng:
email.order.track=Theo dõi đơn hàng
email.order.subject=Đơn hàng #{0} đã được xác nhận
email.footer.copyright=© 2024 Công ty. Bảo lưu mọi quyền.
email.footer.unsubscribe=Hủy đăng ký
```

**5. Reusable layout với th:fragment:**
```html
<!-- templates/email/layout/base.html -->
<!DOCTYPE html>
<html xmlns:th="http://www.thymeleaf.org">
<head th:fragment="head(title)">
  <meta charset="UTF-8">
  <title th:text="${title}">Email</title>
  <style th:replace="~{email/layout/styles :: common}"></style>
</head>

<body>
  <div th:fragment="header" class="header">
    <img th:src="@{/images/logo.png}" alt="Logo">
  </div>

  <div th:fragment="footer" class="footer">
    <p th:text="#{email.footer.copyright}">© 2024</p>
    <p>
      <a th:href="@{${unsubscribeUrl}}" th:text="#{email.footer.unsubscribe}">
        Unsubscribe
      </a>
    </p>
  </div>
</body>
</html>
```

**6. Sử dụng layout:**
```html
<!DOCTYPE html>
<html xmlns:th="http://www.thymeleaf.org">
<head th:replace="~{email/layout/base :: head('Order Confirmation')}"></head>
<body>
  <div th:replace="~{email/layout/base :: header}"></div>

  <div class="content">
    <!-- Email-specific content -->
  </div>

  <div th:replace="~{email/layout/base :: footer}"></div>
</body>
</html>
```

### ❌ Cách sai

```java
// ❌ 1. Hardcoded HTML trong code
@Service
public class BadEmailService {

  public void sendEmail(String to, Order order) {
    String html = "<html><body>" +
                  "<h1>Order Confirmation</h1>" +
                  "<p>Hello " + order.getCustomerName() + ",</p>" +
                  "<p>Order #" + order.getId() + " confirmed.</p>" +
                  "</body></html>";
    // Send email...
  }
}

// ❌ 2. String concatenation cho dynamic content
public String buildEmail(Order order) {
  StringBuilder sb = new StringBuilder();
  sb.append("<html><body>");
  sb.append("<h1>").append(order.getTitle()).append("</h1>");
  for (OrderItem item : order.getItems()) {
    sb.append("<p>").append(item.getName()).append("</p>");
  }
  sb.append("</body></html>");
  return sb.toString();
}

// ❌ 3. Không có i18n support
public void sendEmail(Customer customer) {
  // Email luôn tiếng Anh, không theo locale của customer
  String subject = "Order Confirmation";
  String body = "Your order has been confirmed.";
}

// ❌ 4. Inline CSS không có reusability
public String getEmailHtml() {
  return """
    <div style="background: blue; color: white; padding: 20px;">
      <h1 style="font-size: 24px; margin: 0;">Title</h1>
    </div>
    """;
}
```

### Phát hiện

**Regex patterns:**
```regex
# Hardcoded HTML trong Java code
String\s+html\s*=\s*"<html>

# String concatenation cho email
\.append\("<[^>]+>"\)

# Không dùng template engine
mailSender\.send\([^)]*"<html
```

**PMD/Checkstyle rule:**
```xml
<rule name="EmailTemplateRequired">
  <description>Email content should use template engine</description>
  <pattern>
    String.*=.*"&lt;html&gt;.*&lt;/html&gt;"
  </pattern>
</rule>
```

### Checklist

- [ ] Cấu hình `SpringTemplateEngine` với `ClassLoaderTemplateResolver`
- [ ] Email templates trong `resources/templates/email/`
- [ ] Sử dụng Thymeleaf expressions (`th:text`, `th:each`, `th:if`)
- [ ] i18n với `MessageSource` và `messages.properties`
- [ ] Reusable layout với `th:fragment` và `th:replace`
- [ ] Inline CSS trong `<style>` tag (nhiều email client không hỗ trợ external CSS)
- [ ] Test email template với `TemplateEngineTest`
- [ ] Preview template trong browser trước khi deploy
- [ ] Responsive design cho mobile email clients

---

## 18.02 | Async email sending (không block request thread) | 🔴 BẮT BUỘC

### Metadata
- **ID:** `EMAIL_ASYNC_SENDING`
- **Mức độ:** 🔴 BẮT BUỘC
- **Lý do:** Performance, user experience, scalability

### Tại sao?

**Vấn đề với synchronous email:**
```java
// ❌ User phải đợi email gửi xong (2-5 giây) mới nhận response
@PostMapping("/register")
public ResponseEntity<User> register(@RequestBody RegisterRequest request) {
  User user = userService.createUser(request);
  emailService.sendWelcomeEmail(user); // BLOCKS 2-5s
  return ResponseEntity.ok(user);
}
```

**Lợi ích của async email:**
- ✅ Response time giảm từ 3000ms → 50ms
- ✅ User không phải đợi email delivery
- ✅ Tăng throughput của application
- ✅ SMTP timeout không ảnh hưởng request
- ✅ Có thể retry failed emails

### ✅ Cách đúng

**1. Enable async support:**
```java
@Configuration
@EnableAsync
public class AsyncConfig {

  @Bean(name = "emailTaskExecutor")
  public Executor emailTaskExecutor() {
    ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();
    executor.setCorePoolSize(5);
    executor.setMaxPoolSize(10);
    executor.setQueueCapacity(100);
    executor.setThreadNamePrefix("email-");
    executor.setRejectedExecutionHandler(new ThreadPoolExecutor.CallerRunsPolicy());
    executor.setWaitForTasksToCompleteOnShutdown(true);
    executor.setAwaitTerminationSeconds(60);
    executor.initialize();
    return executor;
  }
}
```

**2. Async email service:**
```java
@Service
@RequiredArgsConstructor
@Slf4j
public class EmailService {

  private final JavaMailSender mailSender;
  private final SpringTemplateEngine templateEngine;
  private final EmailAuditRepository auditRepository;

  @Async("emailTaskExecutor")
  public CompletableFuture<Void> sendWelcomeEmailAsync(User user) {
    EmailAudit audit = EmailAudit.builder()
      .recipientEmail(user.getEmail())
      .templateName("welcome")
      .status(EmailStatus.PENDING)
      .build();
    auditRepository.save(audit);

    try {
      sendWelcomeEmail(user);
      audit.setStatus(EmailStatus.SENT);
      audit.setSentAt(Instant.now());
      log.info("Welcome email sent to {}", user.getEmail());
      return CompletableFuture.completedFuture(null);
    } catch (Exception e) {
      audit.setStatus(EmailStatus.FAILED);
      audit.setErrorMessage(e.getMessage());
      log.error("Failed to send welcome email to {}", user.getEmail(), e);
      throw new EmailSendException("Failed to send email", e);
    } finally {
      auditRepository.save(audit);
    }
  }

  private void sendWelcomeEmail(User user) {
    Context context = new Context();
    context.setVariable("username", user.getName());
    context.setVariable("activationUrl", buildActivationUrl(user));

    String html = templateEngine.process("welcome", context);

    MimeMessage message = mailSender.createMimeMessage();
    try {
      MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");
      helper.setTo(user.getEmail());
      helper.setSubject("Welcome to Our Platform");
      helper.setText(html, true);
      helper.setFrom("noreply@example.com");

      mailSender.send(message);
    } catch (MessagingException e) {
      throw new EmailSendException("Failed to create email", e);
    }
  }

  private String buildActivationUrl(User user) {
    return "https://example.com/activate?token=" + user.getActivationToken();
  }
}
```

**3. Controller sử dụng async email:**
```java
@RestController
@RequestMapping("/api/users")
@RequiredArgsConstructor
public class UserController {

  private final UserService userService;
  private final EmailService emailService;

  @PostMapping("/register")
  public ResponseEntity<UserResponse> register(@Valid @RequestBody RegisterRequest request) {
    User user = userService.createUser(request);

    // Async - không đợi email gửi xong
    emailService.sendWelcomeEmailAsync(user);

    return ResponseEntity.status(HttpStatus.CREATED)
      .body(UserResponse.from(user));
  }

  @PostMapping("/{id}/reset-password")
  public ResponseEntity<Void> resetPassword(@PathVariable Long id) {
    User user = userService.findById(id);
    String resetToken = userService.generateResetToken(user);

    // Fire and forget
    emailService.sendPasswordResetEmailAsync(user, resetToken);

    return ResponseEntity.accepted().build();
  }
}
```

**4. Email audit entity (tracking):**
```java
@Entity
@Table(name = "email_audits")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class EmailAudit {

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Long id;

  @Column(nullable = false)
  private String recipientEmail;

  @Column(nullable = false)
  private String templateName;

  @Enumerated(EnumType.STRING)
  @Column(nullable = false)
  private EmailStatus status;

  @Column(columnDefinition = "TEXT")
  private String errorMessage;

  @Column(nullable = false)
  private Instant createdAt = Instant.now();

  private Instant sentAt;

  @Column(nullable = false)
  private Integer retryCount = 0;

  @Column
  private Instant nextRetryAt;
}

public enum EmailStatus {
  PENDING,
  SENT,
  FAILED,
  RETRYING,
  PERMANENTLY_FAILED
}
```

**5. Advanced: CompletableFuture chaining:**
```java
@Service
@RequiredArgsConstructor
public class OrderService {

  private final OrderRepository orderRepository;
  private final EmailService emailService;
  private final NotificationService notificationService;

  @Transactional
  public Order createOrder(CreateOrderRequest request) {
    Order order = orderRepository.save(Order.from(request));

    // Gửi email và notification song song
    CompletableFuture<Void> emailFuture = emailService.sendOrderConfirmationAsync(order);
    CompletableFuture<Void> notificationFuture = notificationService.sendPushNotificationAsync(order);

    // Đợi cả hai xong (không block request thread)
    CompletableFuture.allOf(emailFuture, notificationFuture)
      .exceptionally(ex -> {
        log.error("Failed to send notifications for order {}", order.getId(), ex);
        return null;
      });

    return order;
  }
}
```

**6. Testing async email:**
```java
@SpringBootTest
@TestPropertySource(properties = {
  "spring.mail.host=localhost",
  "spring.mail.port=3025"
})
class EmailServiceTest {

  @Autowired
  private EmailService emailService;

  @Autowired
  private EmailAuditRepository auditRepository;

  @Test
  void shouldSendWelcomeEmailAsynchronously() throws Exception {
    User user = User.builder()
      .email("test@example.com")
      .name("Test User")
      .build();

    CompletableFuture<Void> future = emailService.sendWelcomeEmailAsync(user);

    // Đợi async task complete
    future.get(5, TimeUnit.SECONDS);

    // Verify audit log
    Optional<EmailAudit> audit = auditRepository
      .findTopByRecipientEmailOrderByCreatedAtDesc("test@example.com");

    assertThat(audit).isPresent();
    assertThat(audit.get().getStatus()).isEqualTo(EmailStatus.SENT);
  }
}
```

### ❌ Cách sai

```java
// ❌ 1. Synchronous email blocking request
@PostMapping("/register")
public ResponseEntity<User> register(@RequestBody RegisterRequest request) {
  User user = userService.createUser(request);
  emailService.sendWelcomeEmail(user); // BLOCKS 3000ms
  return ResponseEntity.ok(user);
}

// ❌ 2. @Async nhưng không configure ThreadPoolTaskExecutor
@Configuration
@EnableAsync
public class BadAsyncConfig {
  // Dùng SimpleAsyncTaskExecutor (tạo thread mới mỗi lần)
  // Không có thread pool, không có queue limit
}

// ❌ 3. @Async trong cùng class (self-invocation)
@Service
public class BadEmailService {

  public void registerUser(User user) {
    // Save user...
    sendEmailAsync(user); // ❌ KHÔNG ASYNC vì self-invocation
  }

  @Async
  public void sendEmailAsync(User user) {
    // This will NOT run asynchronously
  }
}

// ❌ 4. Không handle exception trong async method
@Async
public void sendEmailAsync(User user) {
  // Exception sẽ bị nuốt, không ai biết email failed
  mailSender.send(createMessage(user));
}

// ❌ 5. Không có timeout cho async operation
@Async
public CompletableFuture<Void> sendEmailAsync(User user) {
  // Nếu SMTP server timeout, thread sẽ bị stuck mãi mãi
  mailSender.send(createMessage(user));
  return CompletableFuture.completedFuture(null);
}
```

### Phát hiện

**Regex patterns:**
```regex
# Synchronous email trong controller
@PostMapping.*\n.*emailService\.(send|sendEmail)\(

# @Async không có executor name
@Async\s*\n\s*public

# Self-invocation của @Async method
public.*\{[\s\S]*this\.[a-zA-Z]+Async\(
```

**ArchUnit test:**
```java
@ArchTest
static final ArchRule emailServiceShouldBeAsync =
  methods()
    .that().areDeclaredIn(EmailService.class)
    .and().haveNameMatching("send.*")
    .should().beAnnotatedWith(Async.class);
```

### Checklist

- [ ] Cấu hình `@EnableAsync` với `ThreadPoolTaskExecutor`
- [ ] Email methods annotated với `@Async("emailTaskExecutor")`
- [ ] Return type là `CompletableFuture<Void>` hoặc `void`
- [ ] Exception handling trong async method
- [ ] Email audit log (PENDING → SENT/FAILED)
- [ ] Controller không đợi email gửi xong
- [ ] Response time < 100ms (không bị block bởi email)
- [ ] Test async behavior với `CompletableFuture.get(timeout)`
- [ ] Configure graceful shutdown (`waitForTasksToCompleteOnShutdown`)

---

## 18.03 | Retry failed email deliveries | 🟠 KHUYẾN NGHỊ

### Metadata
- **ID:** `EMAIL_RETRY_MECHANISM`
- **Mức độ:** 🟠 KHUYẾN NGHỊ
- **Lý do:** Reliability, transient failure handling

### Tại sao?

**Email delivery có thể thất bại tạm thời:**
- SMTP server timeout
- Network connectivity issues
- Recipient server temporarily unavailable
- Rate limiting
- Authentication failures

**Retry strategy giúp:**
- ✅ Tăng success rate từ 95% → 99.5%
- ✅ Handle transient failures tự động
- ✅ Exponential backoff tránh overwhelm server
- ✅ Giảm false negative (email failed nhưng thực ra có thể gửi được)

### ✅ Cách đúng

**1. Spring Retry configuration:**
```java
@Configuration
@EnableRetry
public class RetryConfig {

  @Bean
  public RetryTemplate emailRetryTemplate() {
    RetryTemplate retryTemplate = new RetryTemplate();

    // Exponential backoff: 1s, 2s, 4s, 8s, 16s
    ExponentialBackOffPolicy backOffPolicy = new ExponentialBackOffPolicy();
    backOffPolicy.setInitialInterval(1000);
    backOffPolicy.setMultiplier(2.0);
    backOffPolicy.setMaxInterval(30000);
    retryTemplate.setBackOffPolicy(backOffPolicy);

    // Retry up to 5 times
    SimpleRetryPolicy retryPolicy = new SimpleRetryPolicy();
    retryPolicy.setMaxAttempts(5);
    retryTemplate.setRetryPolicy(retryPolicy);

    return retryTemplate;
  }
}
```

**2. Email service với @Retryable:**
```java
@Service
@RequiredArgsConstructor
@Slf4j
public class EmailService {

  private final JavaMailSender mailSender;
  private final SpringTemplateEngine templateEngine;
  private final EmailAuditRepository auditRepository;

  @Async("emailTaskExecutor")
  @Retryable(
    value = {MailSendException.class, MessagingException.class},
    maxAttempts = 5,
    backoff = @Backoff(
      delay = 1000,
      multiplier = 2.0,
      maxDelay = 30000
    )
  )
  public CompletableFuture<Void> sendEmailWithRetry(EmailRequest request) {
    EmailAudit audit = createAudit(request);

    try {
      log.info("Attempting to send email to {} (attempt {})",
        request.getTo(), audit.getRetryCount() + 1);

      sendEmail(request);

      audit.setStatus(EmailStatus.SENT);
      audit.setSentAt(Instant.now());
      auditRepository.save(audit);

      return CompletableFuture.completedFuture(null);

    } catch (MailSendException | MessagingException e) {
      audit.setRetryCount(audit.getRetryCount() + 1);
      audit.setErrorMessage(e.getMessage());
      auditRepository.save(audit);

      log.warn("Email send failed (attempt {}): {}",
        audit.getRetryCount(), e.getMessage());

      throw e; // Trigger retry
    }
  }

  @Recover
  public CompletableFuture<Void> recoverFromEmailFailure(
    MailSendException e,
    EmailRequest request
  ) {
    log.error("Email permanently failed after retries: {}", request.getTo(), e);

    EmailAudit audit = auditRepository
      .findTopByRecipientEmailOrderByCreatedAtDesc(request.getTo())
      .orElseThrow();

    audit.setStatus(EmailStatus.PERMANENTLY_FAILED);
    audit.setErrorMessage("Max retries exceeded: " + e.getMessage());
    auditRepository.save(audit);

    // Optional: Send alert to admin
    sendAdminAlert("Email permanently failed", request, e);

    return CompletableFuture.completedFuture(null);
  }

  private void sendEmail(EmailRequest request) throws MessagingException {
    MimeMessage message = mailSender.createMimeMessage();
    MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");
    helper.setTo(request.getTo());
    helper.setSubject(request.getSubject());
    helper.setText(request.getHtmlContent(), true);
    helper.setFrom(request.getFrom());

    mailSender.send(message);
  }

  private EmailAudit createAudit(EmailRequest request) {
    return auditRepository.save(EmailAudit.builder()
      .recipientEmail(request.getTo())
      .templateName(request.getTemplateName())
      .status(EmailStatus.RETRYING)
      .retryCount(0)
      .build());
  }

  private void sendAdminAlert(String title, EmailRequest request, Exception e) {
    // Send Slack/email notification to admin
  }
}
```

**3. Manual retry với RetryTemplate:**
```java
@Service
@RequiredArgsConstructor
public class EmailRetryService {

  private final RetryTemplate emailRetryTemplate;
  private final JavaMailSender mailSender;

  public void sendEmailWithManualRetry(EmailRequest request) {
    emailRetryTemplate.execute(context -> {
      log.info("Sending email (attempt {})", context.getRetryCount() + 1);

      try {
        sendEmail(request);
        return null;
      } catch (MessagingException e) {
        throw new MailSendException("Failed to send email", e);
      }
    }, context -> {
      // Recovery callback
      log.error("All retry attempts exhausted for {}", request.getTo());
      markAsPermanentlyFailed(request);
      return null;
    });
  }

  private void sendEmail(EmailRequest request) throws MessagingException {
    // Send email logic
  }

  private void markAsPermanentlyFailed(EmailRequest request) {
    // Update audit log
  }
}
```

**4. Scheduled retry cho failed emails:**
```java
@Component
@RequiredArgsConstructor
@Slf4j
public class FailedEmailRetryScheduler {

  private final EmailAuditRepository auditRepository;
  private final EmailService emailService;

  @Scheduled(fixedDelay = 300000) // Every 5 minutes
  public void retryFailedEmails() {
    Instant cutoff = Instant.now().minus(1, ChronoUnit.HOURS);

    List<EmailAudit> failedEmails = auditRepository
      .findByStatusAndNextRetryAtBefore(EmailStatus.FAILED, Instant.now());

    log.info("Found {} failed emails to retry", failedEmails.size());

    failedEmails.forEach(audit -> {
      if (audit.getRetryCount() >= 5) {
        audit.setStatus(EmailStatus.PERMANENTLY_FAILED);
        auditRepository.save(audit);
        return;
      }

      EmailRequest request = buildEmailRequest(audit);

      try {
        emailService.sendEmailWithRetry(request);
      } catch (Exception e) {
        log.error("Retry failed for {}", audit.getRecipientEmail(), e);
        audit.setRetryCount(audit.getRetryCount() + 1);
        audit.setNextRetryAt(calculateNextRetry(audit.getRetryCount()));
        auditRepository.save(audit);
      }
    });
  }

  private EmailRequest buildEmailRequest(EmailAudit audit) {
    // Rebuild email request from audit log
    return EmailRequest.builder()
      .to(audit.getRecipientEmail())
      .templateName(audit.getTemplateName())
      .build();
  }

  private Instant calculateNextRetry(int retryCount) {
    long delayMinutes = (long) Math.pow(2, retryCount); // 1, 2, 4, 8, 16
    return Instant.now().plus(delayMinutes, ChronoUnit.MINUTES);
  }
}
```

**5. Repository với retry queries:**
```java
public interface EmailAuditRepository extends JpaRepository<EmailAudit, Long> {

  Optional<EmailAudit> findTopByRecipientEmailOrderByCreatedAtDesc(String email);

  List<EmailAudit> findByStatusAndNextRetryAtBefore(
    EmailStatus status,
    Instant cutoff
  );

  @Query("""
    SELECT e FROM EmailAudit e
    WHERE e.status = 'FAILED'
    AND e.retryCount < 5
    AND e.nextRetryAt < :now
    ORDER BY e.createdAt ASC
    """)
  List<EmailAudit> findEmailsForRetry(@Param("now") Instant now);

  @Query("""
    SELECT COUNT(e) FROM EmailAudit e
    WHERE e.status = 'PERMANENTLY_FAILED'
    AND e.createdAt > :since
    """)
  long countPermanentFailuresSince(@Param("since") Instant since);
}
```

**6. Circuit breaker pattern (Resilience4j):**
```java
@Configuration
public class EmailCircuitBreakerConfig {

  @Bean
  public CircuitBreaker emailCircuitBreaker() {
    CircuitBreakerConfig config = CircuitBreakerConfig.custom()
      .failureRateThreshold(50) // Open circuit if 50% fail
      .waitDurationInOpenState(Duration.ofMinutes(1))
      .slidingWindowSize(10)
      .minimumNumberOfCalls(5)
      .build();

    return CircuitBreaker.of("email-service", config);
  }
}

@Service
@RequiredArgsConstructor
public class ResilientEmailService {

  private final CircuitBreaker emailCircuitBreaker;
  private final JavaMailSender mailSender;

  public void sendEmail(EmailRequest request) {
    Try.of(emailCircuitBreaker.decorateSupplier(() -> {
      sendEmailInternal(request);
      return null;
    })).getOrElseThrow(ex -> new EmailSendException("Circuit breaker open", ex));
  }

  private void sendEmailInternal(EmailRequest request) {
    // Send email logic
  }
}
```

### ❌ Cách sai

```java
// ❌ 1. Không có retry logic
@Async
public void sendEmail(User user) {
  try {
    mailSender.send(createMessage(user));
  } catch (MailSendException e) {
    // Email failed, nhưng không retry
    log.error("Email failed", e);
  }
}

// ❌ 2. Retry ngay lập tức (không có backoff)
public void sendEmailWithBadRetry(EmailRequest request) {
  int maxAttempts = 5;
  for (int i = 0; i < maxAttempts; i++) {
    try {
      mailSender.send(createMessage(request));
      return;
    } catch (MailSendException e) {
      // Retry ngay lập tức = overwhelm server
      log.warn("Attempt {} failed", i + 1);
    }
  }
}

// ❌ 3. Retry mọi exception (kể cả permanent failures)
@Retryable(
  value = Exception.class, // ❌ Retry cả InvalidEmailException
  maxAttempts = 10
)
public void sendEmail(EmailRequest request) {
  // ...
}

// ❌ 4. Không có @Recover callback
@Retryable(maxAttempts = 5)
public void sendEmail(EmailRequest request) {
  mailSender.send(createMessage(request));
  // Nếu retry hết, exception sẽ propagate lên caller
  // Không có recovery logic
}

// ❌ 5. Hardcoded retry logic trong business code
public void createOrder(Order order) {
  orderRepository.save(order);

  // Retry logic lẫn lộn với business logic
  for (int i = 0; i < 3; i++) {
    try {
      emailService.sendOrderConfirmation(order);
      break;
    } catch (Exception e) {
      Thread.sleep(1000 * i);
    }
  }
}
```

### Phát hiện

**Regex patterns:**
```regex
# Email sending không có @Retryable
mailSender\.send\((?!.*@Retryable)

# Retry loop trong code
for\s*\(.*maxAttempts

# Retry mọi Exception
@Retryable\(.*value\s*=\s*Exception\.class
```

**ArchUnit test:**
```java
@ArchTest
static final ArchRule emailServiceShouldHaveRetry =
  methods()
    .that().areDeclaredIn(EmailService.class)
    .and().haveNameMatching("send.*")
    .should().beAnnotatedWith(Retryable.class);
```

### Checklist

- [ ] Cấu hình `@EnableRetry` trong application
- [ ] Email methods annotated với `@Retryable`
- [ ] Exponential backoff policy (1s, 2s, 4s, 8s, ...)
- [ ] Chỉ retry transient exceptions (`MailSendException`, `MessagingException`)
- [ ] `@Recover` method cho permanent failures
- [ ] Email audit log track `retryCount` và `nextRetryAt`
- [ ] Scheduled job retry failed emails
- [ ] Circuit breaker cho SMTP server failures
- [ ] Admin alert cho permanently failed emails
- [ ] Test retry behavior với mock SMTP failures

---

## 18.04 | Email queue cho bulk sending | 🟠 KHUYẾN NGHỊ

### Metadata
- **ID:** `EMAIL_QUEUE_BULK`
- **Mức độ:** 🟠 KHUYẾN NGHỊ
- **Lý do:** Performance, rate limiting, resource management

### Tại sao?

**Vấn đề với immediate bulk email:**
```java
// ❌ Gửi 10,000 emails cùng lúc = overwhelm SMTP server
public void sendNewsletterToAll() {
  List<User> users = userRepository.findAll(); // 10,000 users
  users.forEach(user -> emailService.sendNewsletterAsync(user));
  // Thread pool exhausted, SMTP rate limit exceeded
}
```

**Lợi ích của email queue:**
- ✅ Rate limiting (e.g., 100 emails/minute)
- ✅ Priority queue (transactional emails > marketing)
- ✅ Batch processing hiệu quả
- ✅ Monitoring và statistics
- ✅ Graceful degradation khi SMTP server slow

### ✅ Cách đúng

**1. Email queue entity:**
```java
@Entity
@Table(name = "email_queue", indexes = {
  @Index(name = "idx_status_priority_scheduled",
    columnList = "status,priority,scheduledAt")
})
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class EmailQueue {

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Long id;

  @Column(nullable = false)
  private String recipientEmail;

  @Column(nullable = false)
  private String subject;

  @Column(columnDefinition = "TEXT", nullable = false)
  private String htmlContent;

  @Column
  private String fromEmail = "noreply@example.com";

  @Enumerated(EnumType.STRING)
  @Column(nullable = false)
  private EmailStatus status = EmailStatus.QUEUED;

  @Enumerated(EnumType.STRING)
  @Column(nullable = false)
  private EmailPriority priority = EmailPriority.NORMAL;

  @Column(nullable = false)
  private Instant scheduledAt = Instant.now();

  @Column
  private Instant processedAt;

  @Column(nullable = false)
  private Integer retryCount = 0;

  @Column
  private Instant nextRetryAt;

  @Column(columnDefinition = "TEXT")
  private String errorMessage;

  @Column(nullable = false)
  private Instant createdAt = Instant.now();

  @Column(name = "template_name")
  private String templateName;

  @Column(columnDefinition = "JSON")
  @Convert(converter = JpaConverters.JsonConverter.class)
  private Map<String, Object> templateVariables;
}

public enum EmailPriority {
  CRITICAL(1),   // Password reset, security alerts
  HIGH(2),       // Transactional emails (orders, confirmations)
  NORMAL(3),     // Regular notifications
  LOW(4),        // Newsletters, marketing
  BULK(5);       // Mass campaigns

  private final int order;

  EmailPriority(int order) {
    this.order = order;
  }
}
```

**2. Email queue service:**
```java
@Service
@RequiredArgsConstructor
@Slf4j
public class EmailQueueService {

  private final EmailQueueRepository queueRepository;
  private final SpringTemplateEngine templateEngine;

  public EmailQueue enqueue(EmailQueueRequest request) {
    EmailQueue email = EmailQueue.builder()
      .recipientEmail(request.getRecipientEmail())
      .subject(request.getSubject())
      .htmlContent(request.getHtmlContent())
      .priority(request.getPriority())
      .scheduledAt(request.getScheduledAt())
      .templateName(request.getTemplateName())
      .templateVariables(request.getTemplateVariables())
      .build();

    return queueRepository.save(email);
  }

  public List<EmailQueue> enqueueBulk(BulkEmailRequest request) {
    List<EmailQueue> emails = request.getRecipients().stream()
      .map(recipient -> EmailQueue.builder()
        .recipientEmail(recipient.getEmail())
        .subject(processTemplate(request.getSubjectTemplate(), recipient))
        .templateName(request.getTemplateName())
        .templateVariables(buildVariables(recipient, request))
        .priority(EmailPriority.BULK)
        .build())
      .toList();

    return queueRepository.saveAll(emails);
  }

  public void enqueueWelcomeEmail(User user) {
    enqueue(EmailQueueRequest.builder()
      .recipientEmail(user.getEmail())
      .subject("Welcome to Our Platform")
      .templateName("welcome")
      .priority(EmailPriority.HIGH)
      .templateVariables(Map.of(
        "username", user.getName(),
        "activationUrl", buildActivationUrl(user)
      ))
      .build());
  }

  public void enqueuePasswordReset(User user, String resetToken) {
    enqueue(EmailQueueRequest.builder()
      .recipientEmail(user.getEmail())
      .subject("Password Reset Request")
      .templateName("password-reset")
      .priority(EmailPriority.CRITICAL) // Highest priority
      .templateVariables(Map.of(
        "username", user.getName(),
        "resetUrl", buildResetUrl(resetToken),
        "expiresIn", "24 hours"
      ))
      .build());
  }

  public void enqueueNewsletter(List<User> recipients, Newsletter newsletter) {
    List<EmailQueue> emails = recipients.stream()
      .map(user -> EmailQueue.builder()
        .recipientEmail(user.getEmail())
        .subject(newsletter.getSubject())
        .htmlContent(newsletter.getHtmlContent())
        .priority(EmailPriority.BULK)
        .scheduledAt(newsletter.getScheduledAt()) // Schedule for future
        .build())
      .toList();

    // Batch insert
    queueRepository.saveAll(emails);
    log.info("Enqueued {} newsletter emails", emails.size());
  }

  private String processTemplate(String template, Recipient recipient) {
    Context context = new Context();
    context.setVariables(recipient.getVariables());
    return templateEngine.process(new StringReader(template), context);
  }

  private Map<String, Object> buildVariables(Recipient recipient, BulkEmailRequest request) {
    Map<String, Object> vars = new HashMap<>(request.getCommonVariables());
    vars.putAll(recipient.getVariables());
    return vars;
  }

  private String buildActivationUrl(User user) {
    return "https://example.com/activate?token=" + user.getActivationToken();
  }

  private String buildResetUrl(String resetToken) {
    return "https://example.com/reset-password?token=" + resetToken;
  }
}
```

**3. Email queue processor (scheduled job):**
```java
@Component
@RequiredArgsConstructor
@Slf4j
public class EmailQueueProcessor {

  private final EmailQueueRepository queueRepository;
  private final JavaMailSender mailSender;
  private final SpringTemplateEngine templateEngine;

  private static final int BATCH_SIZE = 100;
  private static final int MAX_EMAILS_PER_MINUTE = 100;

  @Scheduled(fixedDelay = 10000) // Every 10 seconds
  @Transactional
  public void processEmailQueue() {
    List<EmailQueue> emails = queueRepository.findEmailsToProcess(
      PageRequest.of(0, BATCH_SIZE)
    );

    if (emails.isEmpty()) {
      return;
    }

    log.info("Processing {} queued emails", emails.size());

    int sent = 0;
    int failed = 0;

    for (EmailQueue email : emails) {
      try {
        sendEmail(email);
        email.setStatus(EmailStatus.SENT);
        email.setProcessedAt(Instant.now());
        sent++;

        // Rate limiting: sleep if reached limit
        if (sent % MAX_EMAILS_PER_MINUTE == 0) {
          Thread.sleep(60000); // Wait 1 minute
        }

      } catch (Exception e) {
        log.error("Failed to send email {}", email.getId(), e);
        email.setRetryCount(email.getRetryCount() + 1);
        email.setErrorMessage(e.getMessage());

        if (email.getRetryCount() >= 5) {
          email.setStatus(EmailStatus.PERMANENTLY_FAILED);
        } else {
          email.setStatus(EmailStatus.FAILED);
          email.setNextRetryAt(calculateNextRetry(email.getRetryCount()));
        }
        failed++;
      }

      queueRepository.save(email);
    }

    log.info("Email processing complete: {} sent, {} failed", sent, failed);
  }

  private void sendEmail(EmailQueue email) throws MessagingException {
    String htmlContent = email.getHtmlContent();

    // Render template if needed
    if (email.getTemplateName() != null) {
      Context context = new Context();
      context.setVariables(email.getTemplateVariables());
      htmlContent = templateEngine.process(email.getTemplateName(), context);
    }

    MimeMessage message = mailSender.createMimeMessage();
    MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");
    helper.setTo(email.getRecipientEmail());
    helper.setSubject(email.getSubject());
    helper.setText(htmlContent, true);
    helper.setFrom(email.getFromEmail());

    mailSender.send(message);
  }

  private Instant calculateNextRetry(int retryCount) {
    long delayMinutes = (long) Math.pow(2, retryCount);
    return Instant.now().plus(delayMinutes, ChronoUnit.MINUTES);
  }
}
```

**4. Repository với priority-based query:**
```java
public interface EmailQueueRepository extends JpaRepository<EmailQueue, Long> {

  @Query("""
    SELECT e FROM EmailQueue e
    WHERE e.status = 'QUEUED'
    AND e.scheduledAt <= :now
    ORDER BY e.priority ASC, e.scheduledAt ASC
    """)
  List<EmailQueue> findEmailsToProcess(
    @Param("now") Instant now,
    Pageable pageable
  );

  default List<EmailQueue> findEmailsToProcess(Pageable pageable) {
    return findEmailsToProcess(Instant.now(), pageable);
  }

  @Query("""
    SELECT COUNT(e) FROM EmailQueue e
    WHERE e.status = 'QUEUED'
    AND e.priority = :priority
    """)
  long countQueuedByPriority(@Param("priority") EmailPriority priority);

  @Query("""
    SELECT e.status, COUNT(e)
    FROM EmailQueue e
    WHERE e.createdAt > :since
    GROUP BY e.status
    """)
  List<Object[]> getEmailStatistics(@Param("since") Instant since);

  @Modifying
  @Query("""
    DELETE FROM EmailQueue e
    WHERE e.status = 'SENT'
    AND e.processedAt < :cutoff
    """)
  int cleanupSentEmails(@Param("cutoff") Instant cutoff);
}
```

**5. Monitoring và statistics:**
```java
@Service
@RequiredArgsConstructor
public class EmailMonitoringService {

  private final EmailQueueRepository queueRepository;

  public EmailQueueStatistics getStatistics() {
    Instant since = Instant.now().minus(24, ChronoUnit.HOURS);
    List<Object[]> stats = queueRepository.getEmailStatistics(since);

    Map<EmailStatus, Long> statusCounts = stats.stream()
      .collect(Collectors.toMap(
        row -> (EmailStatus) row[0],
        row -> (Long) row[1]
      ));

    return EmailQueueStatistics.builder()
      .queuedCount(queueRepository.countQueuedByPriority(null))
      .sentLast24h(statusCounts.getOrDefault(EmailStatus.SENT, 0L))
      .failedLast24h(statusCounts.getOrDefault(EmailStatus.FAILED, 0L))
      .criticalQueued(queueRepository.countQueuedByPriority(EmailPriority.CRITICAL))
      .build();
  }

  @Scheduled(cron = "0 0 2 * * *") // 2 AM daily
  @Transactional
  public void cleanupOldEmails() {
    Instant cutoff = Instant.now().minus(30, ChronoUnit.DAYS);
    int deleted = queueRepository.cleanupSentEmails(cutoff);
    log.info("Cleaned up {} sent emails older than 30 days", deleted);
  }
}
```

**6. Controller cho bulk email:**
```java
@RestController
@RequestMapping("/api/emails")
@RequiredArgsConstructor
public class EmailController {

  private final EmailQueueService queueService;

  @PostMapping("/send-newsletter")
  @PreAuthorize("hasRole('ADMIN')")
  public ResponseEntity<BulkEmailResponse> sendNewsletter(
    @Valid @RequestBody NewsletterRequest request
  ) {
    List<User> recipients = userService.findSubscribedUsers();

    Newsletter newsletter = Newsletter.builder()
      .subject(request.getSubject())
      .htmlContent(request.getHtmlContent())
      .scheduledAt(request.getScheduledAt())
      .build();

    queueService.enqueueNewsletter(recipients, newsletter);

    return ResponseEntity.accepted()
      .body(BulkEmailResponse.builder()
        .message("Newsletter queued for delivery")
        .recipientCount(recipients.size())
        .scheduledAt(request.getScheduledAt())
        .build());
  }

  @GetMapping("/queue/statistics")
  @PreAuthorize("hasRole('ADMIN')")
  public ResponseEntity<EmailQueueStatistics> getQueueStatistics() {
    return ResponseEntity.ok(emailMonitoringService.getStatistics());
  }
}
```

### ❌ Cách sai

```java
// ❌ 1. Gửi bulk email không qua queue
public void sendNewsletterToAll() {
  List<User> users = userRepository.findAll(); // 10,000 users
  users.forEach(user -> {
    emailService.sendNewsletterAsync(user); // Overwhelm thread pool
  });
}

// ❌ 2. Không có priority queue
@Entity
public class BadEmailQueue {
  // Tất cả emails được process theo FIFO
  // Password reset phải đợi 10,000 marketing emails
}

// ❌ 3. Không có rate limiting
@Scheduled(fixedDelay = 1000)
public void processQueue() {
  List<EmailQueue> all = queueRepository.findAll();
  all.forEach(this::sendEmail); // Gửi hết cùng lúc = rate limit exceeded
}

// ❌ 4. Load toàn bộ template content vào database
public void enqueue(User user, String newsletter) {
  EmailQueue email = new EmailQueue();
  email.setHtmlContent(newsletter); // 100KB HTML × 10,000 users = 1GB
  queueRepository.save(email);
}

// ❌ 5. Không cleanup old emails
// EmailQueue table ngày càng lớn (millions of sent emails)
```

### Phát hiện

**Regex patterns:**
```regex
# Bulk email không qua queue
\.forEach\(.*emailService\.send

# Không có priority trong query
findAll\(\).*ORDER BY created

# Load tất cả emails từ queue
queueRepository\.findAll\(\)
```

**Database index check:**
```sql
-- Kiểm tra index cho priority queue
SELECT * FROM information_schema.statistics
WHERE table_name = 'email_queue'
AND column_name IN ('status', 'priority', 'scheduled_at');
```

### Checklist

- [ ] `EmailQueue` entity với `status`, `priority`, `scheduledAt`
- [ ] Database index: `(status, priority, scheduledAt)`
- [ ] `EmailQueueService.enqueue()` cho individual emails
- [ ] `EmailQueueService.enqueueBulk()` cho bulk campaigns
- [ ] Scheduled job process queue với batch size limit
- [ ] Priority-based processing (CRITICAL > HIGH > NORMAL > LOW > BULK)
- [ ] Rate limiting (e.g., 100 emails/minute)
- [ ] Monitoring dashboard (queued, sent, failed counts)
- [ ] Cleanup job xóa sent emails sau 30 ngày
- [ ] Admin API xem queue statistics

---

## 18.05 | Sanitize user content trong email (XSS prevention) | 🔴 BẮT BUỘC

### Metadata
- **ID:** `EMAIL_XSS_PREVENTION`
- **Mức độ:** 🔴 BẮT BUỘC
- **Lý do:** Security, XSS attack prevention

### Tại sao?

**Email client vulnerabilities:**
```java
// ❌ User-generated content trong email = XSS risk
String message = userRequest.getMessage(); // "<script>alert('XSS')</script>"
emailService.send(user.getEmail(), "New message", message);
// Email client có thể execute script
```

**Attack scenarios:**
- Script injection trong email HTML
- Phishing links disguised as legitimate URLs
- HTML injection để fake sender information
- CSS-based attacks (expression, behavior)

### ✅ Cách đúng

**1. Dependencies:**
```xml
<dependency>
  <groupId>org.owasp.encoder</groupId>
  <artifactId>encoder</artifactId>
  <version>1.2.3</version>
</dependency>

<dependency>
  <groupId>org.jsoup</groupId>
  <artifactId>jsoup</artifactId>
  <version>1.17.2</version>
</dependency>
```

**2. HTML sanitizer service:**
```java
@Service
public class HtmlSanitizerService {

  private final Safelist emailSafelist;

  public HtmlSanitizerService() {
    // Whitelist cho email content
    this.emailSafelist = Safelist.relaxed()
      .addTags("h1", "h2", "h3", "h4", "h5", "h6")
      .addAttributes("a", "href", "title")
      .addAttributes("img", "src", "alt", "width", "height")
      .addProtocols("a", "href", "http", "https", "mailto")
      .addProtocols("img", "src", "http", "https", "data")
      .removeTags("script", "iframe", "object", "embed", "form")
      .removeAttributes("*", "onclick", "onload", "onerror", "style");
  }

  public String sanitizeHtml(String unsafeHtml) {
    if (unsafeHtml == null || unsafeHtml.isBlank()) {
      return "";
    }

    // Remove malicious HTML
    String cleaned = Jsoup.clean(unsafeHtml, emailSafelist);

    // Parse và validate URLs
    Document doc = Jsoup.parse(cleaned);
    doc.select("a[href]").forEach(link -> {
      String href = link.attr("href");
      if (!isValidUrl(href)) {
        link.removeAttr("href");
      }
    });

    return doc.body().html();
  }

  public String sanitizePlainText(String text) {
    if (text == null) {
      return "";
    }

    // HTML encode để prevent XSS
    return Encode.forHtml(text);
  }

  public String sanitizeSubject(String subject) {
    if (subject == null || subject.isBlank()) {
      return "No Subject";
    }

    // Subject không được chứa HTML
    String cleaned = Jsoup.parse(subject).text();

    // Remove control characters
    cleaned = cleaned.replaceAll("[\\p{Cntrl}&&[^\r\n\t]]", "");

    // Limit length
    if (cleaned.length() > 255) {
      cleaned = cleaned.substring(0, 252) + "...";
    }

    return cleaned;
  }

  private boolean isValidUrl(String url) {
    if (url == null || url.isBlank()) {
      return false;
    }

    // Check protocol
    if (!url.startsWith("http://") &&
        !url.startsWith("https://") &&
        !url.startsWith("mailto:")) {
      return false;
    }

    // Check for javascript: protocol
    if (url.toLowerCase().contains("javascript:")) {
      return false;
    }

    return true;
  }
}
```

**3. Email service với sanitization:**
```java
@Service
@RequiredArgsConstructor
public class SecureEmailService {

  private final JavaMailSender mailSender;
  private final SpringTemplateEngine templateEngine;
  private final HtmlSanitizerService sanitizer;

  public void sendUserMessage(User from, User to, String rawMessage) {
    // Sanitize user input
    String safeMessage = sanitizer.sanitizeHtml(rawMessage);
    String safeFromName = sanitizer.sanitizePlainText(from.getName());
    String safeToName = sanitizer.sanitizePlainText(to.getName());

    Context context = new Context();
    context.setVariable("fromName", safeFromName);
    context.setVariable("toName", safeToName);
    context.setVariable("message", safeMessage);
    context.setVariable("messageDate", Instant.now());

    String html = templateEngine.process("user-message", context);

    sendEmail(
      to.getEmail(),
      "New message from " + safeFromName,
      html
    );
  }

  public void sendCommentNotification(Post post, Comment comment) {
    // Sanitize comment content
    String safeContent = sanitizer.sanitizeHtml(comment.getContent());
    String safeAuthorName = sanitizer.sanitizePlainText(comment.getAuthor().getName());
    String safePostTitle = sanitizer.sanitizePlainText(post.getTitle());

    Context context = new Context();
    context.setVariable("postTitle", safePostTitle);
    context.setVariable("authorName", safeAuthorName);
    context.setVariable("commentContent", safeContent);
    context.setVariable("postUrl", buildPostUrl(post));

    String html = templateEngine.process("comment-notification", context);

    sendEmail(
      post.getAuthor().getEmail(),
      "New comment on: " + safePostTitle,
      html
    );
  }

  private void sendEmail(String to, String subject, String htmlContent) {
    // Additional subject sanitization
    String safeSubject = sanitizer.sanitizeSubject(subject);

    MimeMessage message = mailSender.createMimeMessage();
    try {
      MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");
      helper.setTo(to);
      helper.setSubject(safeSubject);
      helper.setText(htmlContent, true);
      helper.setFrom("noreply@example.com");

      mailSender.send(message);
    } catch (MessagingException e) {
      throw new EmailSendException("Failed to send email", e);
    }
  }

  private String buildPostUrl(Post post) {
    return "https://example.com/posts/" + post.getId();
  }
}
```

**4. Template với safe output:**
```html
<!DOCTYPE html>
<html xmlns:th="http://www.thymeleaf.org">
<head>
  <meta charset="UTF-8">
  <title>User Message</title>
</head>
<body>
  <div class="header">
    <h1>New Message</h1>
  </div>

  <div class="content">
    <!-- Safe plain text output -->
    <p>
      <strong>From:</strong>
      <span th:text="${fromName}">John Doe</span>
    </p>

    <p>
      <strong>To:</strong>
      <span th:text="${toName}">Jane Smith</span>
    </p>

    <!-- Safe HTML output (already sanitized) -->
    <div class="message">
      <p th:utext="${message}">Message content here</p>
    </div>

    <!-- NEVER use th:utext with unsanitized user input -->
    <!-- <p th:utext="${rawUserInput}"></p> ❌ DANGEROUS -->
  </div>

  <div class="footer">
    <p>
      <a th:href="@{${replyUrl}}" th:text="#{email.reply}">Reply</a>
    </p>
  </div>
</body>
</html>
```

**5. Validation DTO:**
```java
public record UserMessageRequest(
  @NotBlank(message = "Recipient is required")
  @Email(message = "Invalid email")
  String recipientEmail,

  @NotBlank(message = "Subject is required")
  @Size(max = 255, message = "Subject too long")
  String subject,

  @NotBlank(message = "Message is required")
  @Size(max = 10000, message = "Message too long")
  String message
) {

  public UserMessageRequest {
    // Constructor validation
    if (subject != null && subject.contains("<script>")) {
      throw new IllegalArgumentException("Invalid subject");
    }

    if (message != null && message.length() > 10000) {
      throw new IllegalArgumentException("Message too long");
    }
  }
}
```

**6. Controller với sanitization:**
```java
@RestController
@RequestMapping("/api/messages")
@RequiredArgsConstructor
public class MessageController {

  private final SecureEmailService emailService;
  private final UserService userService;
  private final HtmlSanitizerService sanitizer;

  @PostMapping("/send")
  public ResponseEntity<MessageResponse> sendMessage(
    @Valid @RequestBody UserMessageRequest request,
    @AuthenticationPrincipal UserPrincipal currentUser
  ) {
    // Double sanitization: DTO validation + explicit sanitization
    String safeMessage = sanitizer.sanitizeHtml(request.message());
    String safeSubject = sanitizer.sanitizeSubject(request.subject());

    User from = userService.findById(currentUser.getId());
    User to = userService.findByEmail(request.recipientEmail());

    emailService.sendUserMessage(from, to, safeMessage);

    return ResponseEntity.ok(MessageResponse.builder()
      .message("Message sent successfully")
      .build());
  }
}
```

### ❌ Cách sai

```java
// ❌ 1. Không sanitize user input
public void sendEmail(String to, String subject, String message) {
  // message có thể chứa <script>alert('XSS')</script>
  MimeMessageHelper helper = new MimeMessageHelper(mimeMessage);
  helper.setText(message, true); // HTML = true, nhưng không sanitize
  mailSender.send(mimeMessage);
}

// ❌ 2. Sử dụng th:utext với unsanitized input
<!-- Template -->
<div th:utext="${userComment}"></div>
<!-- Nếu userComment = "<script>steal()</script>" = XSS -->

// ❌ 3. Chỉ validate phía frontend
// Frontend: input.replace(/<script>/g, '')
// Attacker bypass bằng Postman/curl

// ❌ 4. Blacklist thay vì whitelist
public String sanitize(String html) {
  return html
    .replace("<script>", "")
    .replace("javascript:", "")
    .replace("onerror=", "");
  // Bypass: <scr<script>ipt>, javascri&#x70;t:
}

// ❌ 5. Trust user-provided URLs
<a th:href="${userProvidedUrl}">Click here</a>
<!-- userProvidedUrl = "javascript:alert('XSS')" -->
```

### Phát hiện

**Regex patterns:**
```regex
# th:utext không có sanitization
th:utext="\$\{[^}]+\}"

# setText(html, true) không có sanitization
setText\([^,]+,\s*true\)

# Blacklist-based filtering
\.replace\("<script>"

# Không validate URL protocol
href="\$\{[^}]+\}"
```

**OWASP Dependency Check:**
```xml
<plugin>
  <groupId>org.owasp</groupId>
  <artifactId>dependency-check-maven</artifactId>
  <configuration>
    <failBuildOnCVSS>7</failBuildOnCVSS>
  </configuration>
</plugin>
```

### Checklist

- [ ] Jsoup dependency trong `pom.xml`
- [ ] `HtmlSanitizerService` với whitelist-based cleaning
- [ ] Sanitize ALL user input trước khi đưa vào email
- [ ] Validate URL protocols (http, https, mailto only)
- [ ] Remove dangerous attributes (`onclick`, `onerror`, `style`)
- [ ] Sanitize email subject (remove HTML, control chars)
- [ ] Use `th:text` cho plain text, `th:utext` CHỈ cho sanitized HTML
- [ ] Content-Security-Policy header (nếu email client hỗ trợ)
- [ ] Limit message length (prevent DoS)
- [ ] Test với OWASP XSS payloads

---

## 18.06 | Unsubscribe mechanism compliance | 🟡 NÊN CÓ

### Metadata
- **ID:** `EMAIL_UNSUBSCRIBE_COMPLIANCE`
- **Mức độ:** 🟡 NÊN CÓ
- **Lý do:** Legal compliance (CAN-SPAM, GDPR), user experience

### Tại sao?

**Legal requirements:**
- CAN-SPAM Act (US): Phạt $43,280 per email nếu không có unsubscribe
- GDPR (EU): Phạt up to €20M hoặc 4% revenue
- Reputation: Email provider (Gmail, Outlook) mark as spam nếu không comply

**User experience:**
- Dễ dàng unsubscribe = giảm spam complaints
- One-click unsubscribe = tốt hơn login + settings

### ✅ Cách đúng

**1. Unsubscribe entity:**
```java
@Entity
@Table(name = "email_subscriptions", indexes = {
  @Index(name = "idx_user_category", columnList = "userId,category", unique = true)
})
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class EmailSubscription {

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Long id;

  @Column(nullable = false)
  private Long userId;

  @ManyToOne(fetch = FetchType.LAZY)
  @JoinColumn(name = "userId", insertable = false, updatable = false)
  private User user;

  @Enumerated(EnumType.STRING)
  @Column(nullable = false)
  private EmailCategory category;

  @Column(nullable = false)
  private Boolean subscribed = true;

  @Column(nullable = false, unique = true)
  private String unsubscribeToken = UUID.randomUUID().toString();

  @Column(nullable = false)
  private Instant createdAt = Instant.now();

  @Column
  private Instant unsubscribedAt;

  @Column
  private String unsubscribeReason;
}

public enum EmailCategory {
  TRANSACTIONAL,    // Không thể unsubscribe (order confirmations)
  NOTIFICATIONS,    // Platform notifications
  NEWSLETTER,       // Marketing emails
  PROMOTIONS,       // Promotional campaigns
  PRODUCT_UPDATES,  // Product announcements
  ALL               // Unsubscribe from everything (except TRANSACTIONAL)
}
```

**2. Unsubscribe service:**
```java
@Service
@RequiredArgsConstructor
@Slf4j
public class UnsubscribeService {

  private final EmailSubscriptionRepository subscriptionRepository;
  private final UserRepository userRepository;

  @Transactional
  public void unsubscribe(String token, EmailCategory category) {
    EmailSubscription subscription = subscriptionRepository
      .findByUnsubscribeToken(token)
      .orElseThrow(() -> new UnsubscribeTokenNotFoundException(token));

    if (category == EmailCategory.TRANSACTIONAL) {
      throw new IllegalArgumentException("Cannot unsubscribe from transactional emails");
    }

    if (category == EmailCategory.ALL) {
      // Unsubscribe from all except TRANSACTIONAL
      subscriptionRepository.unsubscribeAllExceptTransactional(subscription.getUserId());
      log.info("User {} unsubscribed from all email categories", subscription.getUserId());
    } else {
      subscription.setSubscribed(false);
      subscription.setUnsubscribedAt(Instant.now());
      subscriptionRepository.save(subscription);
      log.info("User {} unsubscribed from {}", subscription.getUserId(), category);
    }
  }

  @Transactional
  public void unsubscribeWithReason(String token, EmailCategory category, String reason) {
    unsubscribe(token, category);

    EmailSubscription subscription = subscriptionRepository
      .findByUnsubscribeToken(token)
      .orElseThrow();

    subscription.setUnsubscribeReason(reason);
    subscriptionRepository.save(subscription);
  }

  @Transactional
  public void resubscribe(Long userId, EmailCategory category) {
    EmailSubscription subscription = subscriptionRepository
      .findByUserIdAndCategory(userId, category)
      .orElseGet(() -> createSubscription(userId, category));

    subscription.setSubscribed(true);
    subscription.setUnsubscribedAt(null);
    subscriptionRepository.save(subscription);
  }

  public boolean isSubscribed(Long userId, EmailCategory category) {
    // TRANSACTIONAL emails always allowed
    if (category == EmailCategory.TRANSACTIONAL) {
      return true;
    }

    return subscriptionRepository
      .findByUserIdAndCategory(userId, category)
      .map(EmailSubscription::getSubscribed)
      .orElse(true); // Default subscribed
  }

  public String generateUnsubscribeUrl(User user, EmailCategory category) {
    EmailSubscription subscription = subscriptionRepository
      .findByUserIdAndCategory(user.getId(), category)
      .orElseGet(() -> createSubscription(user.getId(), category));

    return "https://example.com/unsubscribe?token=" +
           subscription.getUnsubscribeToken() +
           "&category=" + category.name();
  }

  public Map<EmailCategory, Boolean> getUserPreferences(Long userId) {
    List<EmailSubscription> subscriptions = subscriptionRepository
      .findByUserId(userId);

    return Arrays.stream(EmailCategory.values())
      .collect(Collectors.toMap(
        category -> category,
        category -> subscriptions.stream()
          .filter(sub -> sub.getCategory() == category)
          .findFirst()
          .map(EmailSubscription::getSubscribed)
          .orElse(true)
      ));
  }

  private EmailSubscription createSubscription(Long userId, EmailCategory category) {
    return subscriptionRepository.save(EmailSubscription.builder()
      .userId(userId)
      .category(category)
      .subscribed(true)
      .build());
  }
}
```

**3. Email service với unsubscribe check:**
```java
@Service
@RequiredArgsConstructor
public class EmailService {

  private final UnsubscribeService unsubscribeService;
  private final JavaMailSender mailSender;
  private final SpringTemplateEngine templateEngine;

  public void sendNewsletter(User user, Newsletter newsletter) {
    // Check subscription status
    if (!unsubscribeService.isSubscribed(user.getId(), EmailCategory.NEWSLETTER)) {
      log.info("User {} unsubscribed from newsletters, skipping", user.getId());
      return;
    }

    String unsubscribeUrl = unsubscribeService
      .generateUnsubscribeUrl(user, EmailCategory.NEWSLETTER);

    Context context = new Context();
    context.setVariable("username", user.getName());
    context.setVariable("newsletterContent", newsletter.getContent());
    context.setVariable("unsubscribeUrl", unsubscribeUrl);

    String html = templateEngine.process("newsletter", context);

    sendEmailWithUnsubscribe(
      user.getEmail(),
      newsletter.getSubject(),
      html,
      unsubscribeUrl
    );
  }

  private void sendEmailWithUnsubscribe(
    String to,
    String subject,
    String html,
    String unsubscribeUrl
  ) {
    MimeMessage message = mailSender.createMimeMessage();
    try {
      MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");
      helper.setTo(to);
      helper.setSubject(subject);
      helper.setText(html, true);
      helper.setFrom("noreply@example.com");

      // List-Unsubscribe header (RFC 2369)
      message.addHeader("List-Unsubscribe", "<" + unsubscribeUrl + ">");

      // List-Unsubscribe-Post header (RFC 8058) - one-click unsubscribe
      message.addHeader("List-Unsubscribe-Post", "List-Unsubscribe=One-Click");

      mailSender.send(message);
    } catch (MessagingException e) {
      throw new EmailSendException("Failed to send email", e);
    }
  }
}
```

**4. Unsubscribe controller:**
```java
@Controller
@RequestMapping("/unsubscribe")
@RequiredArgsConstructor
public class UnsubscribeController {

  private final UnsubscribeService unsubscribeService;

  @GetMapping
  public String showUnsubscribePage(
    @RequestParam String token,
    @RequestParam(required = false) EmailCategory category,
    Model model
  ) {
    model.addAttribute("token", token);
    model.addAttribute("category", category != null ? category : EmailCategory.ALL);
    model.addAttribute("categories", EmailCategory.values());
    return "unsubscribe";
  }

  @PostMapping
  public String processUnsubscribe(
    @RequestParam String token,
    @RequestParam EmailCategory category,
    @RequestParam(required = false) String reason,
    Model model
  ) {
    try {
      if (reason != null && !reason.isBlank()) {
        unsubscribeService.unsubscribeWithReason(token, category, reason);
      } else {
        unsubscribeService.unsubscribe(token, category);
      }

      model.addAttribute("success", true);
      model.addAttribute("category", category);
      return "unsubscribe-success";

    } catch (Exception e) {
      model.addAttribute("error", e.getMessage());
      return "unsubscribe-error";
    }
  }

  // One-click unsubscribe endpoint (RFC 8058)
  @PostMapping("/one-click")
  public ResponseEntity<Void> oneClickUnsubscribe(@RequestParam String token) {
    try {
      unsubscribeService.unsubscribe(token, EmailCategory.ALL);
      return ResponseEntity.ok().build();
    } catch (Exception e) {
      return ResponseEntity.badRequest().build();
    }
  }
}

@RestController
@RequestMapping("/api/email-preferences")
@RequiredArgsConstructor
public class EmailPreferencesController {

  private final UnsubscribeService unsubscribeService;

  @GetMapping
  public ResponseEntity<Map<EmailCategory, Boolean>> getPreferences(
    @AuthenticationPrincipal UserPrincipal currentUser
  ) {
    Map<EmailCategory, Boolean> preferences =
      unsubscribeService.getUserPreferences(currentUser.getId());
    return ResponseEntity.ok(preferences);
  }

  @PutMapping("/{category}")
  public ResponseEntity<Void> updatePreference(
    @PathVariable EmailCategory category,
    @RequestParam Boolean subscribed,
    @AuthenticationPrincipal UserPrincipal currentUser
  ) {
    if (subscribed) {
      unsubscribeService.resubscribe(currentUser.getId(), category);
    } else {
      String token = unsubscribeService
        .getUserSubscriptionToken(currentUser.getId(), category);
      unsubscribeService.unsubscribe(token, category);
    }

    return ResponseEntity.ok().build();
  }
}
```

**5. Email template với unsubscribe link:**
```html
<!DOCTYPE html>
<html xmlns:th="http://www.thymeleaf.org">
<head>
  <meta charset="UTF-8">
  <title>Newsletter</title>
</head>
<body>
  <div class="content">
    <h1>Monthly Newsletter</h1>

    <div th:utext="${newsletterContent}">
      Newsletter content here...
    </div>
  </div>

  <div class="footer" style="margin-top: 40px; padding-top: 20px; border-top: 1px solid #ccc; font-size: 12px; color: #666;">
    <p>
      <strong>Manage your email preferences:</strong>
    </p>
    <p>
      You're receiving this email because you subscribed to our newsletter.
    </p>
    <p>
      <a th:href="@{${unsubscribeUrl}}" style="color: #007bff;">
        Unsubscribe from newsletters
      </a>
      |
      <a th:href="@{${preferencesUrl}}" style="color: #007bff;">
        Manage all preferences
      </a>
    </p>
    <p style="margin-top: 10px;">
      <small>
        Our mailing address is: 123 Main St, City, State 12345
      </small>
    </p>
  </div>
</body>
</html>
```

**6. Unsubscribe page (Thymeleaf):**
```html
<!DOCTYPE html>
<html xmlns:th="http://www.thymeleaf.org">
<head>
  <meta charset="UTF-8">
  <title>Unsubscribe</title>
  <style>
    body { font-family: Arial, sans-serif; max-width: 600px; margin: 50px auto; padding: 20px; }
    .btn { padding: 10px 20px; background: #dc3545; color: white; border: none; cursor: pointer; }
    .radio-group { margin: 20px 0; }
  </style>
</head>
<body>
  <h1>Manage Email Preferences</h1>

  <p>We're sorry to see you go. Please select which emails you'd like to unsubscribe from:</p>

  <form method="post" th:action="@{/unsubscribe}">
    <input type="hidden" name="token" th:value="${token}">

    <div class="radio-group">
      <div th:each="cat : ${categories}">
        <label th:if="${cat != T(com.example.EmailCategory).TRANSACTIONAL}">
          <input type="radio" name="category" th:value="${cat}"
            th:checked="${cat == category}">
          <span th:text="${cat}">Category</span>
        </label>
      </div>
    </div>

    <div>
      <label>Reason for unsubscribing (optional):</label>
      <select name="reason">
        <option value="">Select a reason...</option>
        <option value="TOO_FREQUENT">Too many emails</option>
        <option value="NOT_RELEVANT">Content not relevant</option>
        <option value="NO_LONGER_NEEDED">No longer need this service</option>
        <option value="OTHER">Other</option>
      </select>
    </div>

    <button type="submit" class="btn">Unsubscribe</button>
  </form>
</body>
</html>
```

### ❌ Cách sai

```java
// ❌ 1. Không có unsubscribe link
public void sendNewsletter(User user) {
  // Send email without unsubscribe option = vi phạm CAN-SPAM
}

// ❌ 2. Yêu cầu login để unsubscribe
@GetMapping("/unsubscribe")
@PreAuthorize("isAuthenticated()") // ❌ User phải login
public String unsubscribe() {
  // Should be one-click, không cần login
}

// ❌ 3. Không check subscription status
public void sendPromotion(List<User> users) {
  users.forEach(user -> {
    // Gửi cho tất cả users, kể cả người đã unsubscribe
    emailService.send(user.getEmail(), promotion);
  });
}

// ❌ 4. Unsubscribe token dễ đoán
public String generateUnsubscribeUrl(User user) {
  // ❌ userId có thể đoán được
  return "https://example.com/unsubscribe?userId=" + user.getId();
}

// ❌ 5. Không có List-Unsubscribe header
public void sendEmail(String to, String html) {
  MimeMessageHelper helper = new MimeMessageHelper(message);
  helper.setText(html, true);
  // Missing List-Unsubscribe header
  mailSender.send(message);
}
```

### Phát hiện

**Regex patterns:**
```regex
# Email template không có unsubscribe
<body>(?!.*unsubscribe).*</body>

# SendEmail không có List-Unsubscribe header
mailSender\.send\((?!.*List-Unsubscribe)

# Unsubscribe endpoint yêu cầu auth
@PreAuthorize.*\n.*@GetMapping.*unsubscribe
```

**Compliance check:**
```java
@Test
void newsletterEmailShouldHaveUnsubscribeLink() {
  String html = emailService.renderNewsletter(user, newsletter);
  assertThat(html).contains("unsubscribe");
  assertThat(html).containsPattern("href=.*unsubscribe.*token=");
}

@Test
void emailShouldHaveListUnsubscribeHeader() throws MessagingException {
  MimeMessage message = emailService.createNewsletterMessage(user);
  String[] headers = message.getHeader("List-Unsubscribe");
  assertThat(headers).isNotEmpty();
  assertThat(headers[0]).startsWith("http");
}
```

### Checklist

- [ ] `EmailSubscription` entity với `unsubscribeToken`
- [ ] Unsubscribe link trong EVERY marketing email footer
- [ ] `List-Unsubscribe` header trong email
- [ ] `List-Unsubscribe-Post` header (one-click)
- [ ] Unsubscribe page không yêu cầu login
- [ ] Check `isSubscribed()` trước khi gửi marketing email
- [ ] TRANSACTIONAL emails không thể unsubscribe (order confirmations)
- [ ] Unsubscribe reasons tracking (analytics)
- [ ] Physical mailing address trong footer (CAN-SPAM requirement)
- [ ] Test unsubscribe flow end-to-end

---

## 18.07 | Email delivery tracking (sent, bounced, opened) | 🟡 NÊN CÓ

### Metadata
- **ID:** `EMAIL_DELIVERY_TRACKING`
- **Mức độ:** 🟡 NÊN CÓ
- **Lý do:** Analytics, deliverability monitoring, bounce handling

### Tại sao?

**Business value:**
- Biết email có đến user không (deliverability rate)
- Bounce rate cao = email list cần clean up
- Open rate thấp = subject line cần cải thiện
- Click tracking = measure campaign effectiveness

**Technical value:**
- Detect invalid email addresses tự động
- Monitor SMTP server health
- A/B testing email campaigns

### ✅ Cách đúng

**1. Email tracking entity:**
```java
@Entity
@Table(name = "email_tracking", indexes = {
  @Index(name = "idx_message_id", columnList = "messageId"),
  @Index(name = "idx_recipient", columnList = "recipientEmail"),
  @Index(name = "idx_sent_at", columnList = "sentAt")
})
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class EmailTracking {

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Long id;

  @Column(nullable = false, unique = true)
  private String messageId; // SMTP Message-ID

  @Column(nullable = false)
  private String recipientEmail;

  @Column(nullable = false)
  private String subject;

  @Column(nullable = false)
  private String templateName;

  @Enumerated(EnumType.STRING)
  @Column(nullable = false)
  private EmailStatus status = EmailStatus.PENDING;

  @Column(nullable = false)
  private Instant sentAt;

  @Column
  private Instant deliveredAt;

  @Column
  private Instant bouncedAt;

  @Column
  private Instant openedAt;

  @Column
  private Integer openCount = 0;

  @Column
  private Instant firstClickedAt;

  @Column
  private Integer clickCount = 0;

  @Enumerated(EnumType.STRING)
  private BounceType bounceType;

  @Column(columnDefinition = "TEXT")
  private String bounceReason;

  @Column
  private String userAgent;

  @Column
  private String ipAddress;

  @Column(nullable = false)
  private Instant createdAt = Instant.now();
}

public enum BounceType {
  HARD_BOUNCE,   // Permanent failure (invalid email)
  SOFT_BOUNCE,   // Temporary failure (mailbox full)
  COMPLAINT      // User marked as spam
}
```

**2. Email tracking service:**
```java
@Service
@RequiredArgsConstructor
@Slf4j
public class EmailTrackingService {

  private final EmailTrackingRepository trackingRepository;
  private final UserRepository userRepository;

  public EmailTracking createTracking(MimeMessage message, String templateName)
      throws MessagingException {
    String messageId = message.getMessageID();
    String[] recipients = message.getRecipients(Message.RecipientType.TO);
    String recipientEmail = recipients[0].toString();

    return trackingRepository.save(EmailTracking.builder()
      .messageId(messageId)
      .recipientEmail(recipientEmail)
      .subject(message.getSubject())
      .templateName(templateName)
      .status(EmailStatus.SENT)
      .sentAt(Instant.now())
      .build());
  }

  @Transactional
  public void trackOpen(String trackingId, String userAgent, String ipAddress) {
    EmailTracking tracking = trackingRepository.findByMessageId(trackingId)
      .orElseThrow(() -> new TrackingNotFoundException(trackingId));

    if (tracking.getOpenedAt() == null) {
      tracking.setOpenedAt(Instant.now());
      log.info("Email {} opened for the first time", trackingId);
    }

    tracking.setOpenCount(tracking.getOpenCount() + 1);
    tracking.setUserAgent(userAgent);
    tracking.setIpAddress(ipAddress);
    tracking.setStatus(EmailStatus.OPENED);

    trackingRepository.save(tracking);
  }

  @Transactional
  public void trackClick(String trackingId, String url) {
    EmailTracking tracking = trackingRepository.findByMessageId(trackingId)
      .orElseThrow(() -> new TrackingNotFoundException(trackingId));

    if (tracking.getFirstClickedAt() == null) {
      tracking.setFirstClickedAt(Instant.now());
    }

    tracking.setClickCount(tracking.getClickCount() + 1);
    trackingRepository.save(tracking);

    // Optional: Track specific link clicks
    linkClickRepository.save(LinkClick.builder()
      .emailTrackingId(tracking.getId())
      .url(url)
      .clickedAt(Instant.now())
      .build());
  }

  @Transactional
  public void trackBounce(String messageId, BounceType bounceType, String reason) {
    EmailTracking tracking = trackingRepository.findByMessageId(messageId)
      .orElseThrow(() -> new TrackingNotFoundException(messageId));

    tracking.setStatus(EmailStatus.BOUNCED);
    tracking.setBouncedAt(Instant.now());
    tracking.setBounceType(bounceType);
    tracking.setBounceReason(reason);

    trackingRepository.save(tracking);

    // Handle hard bounces
    if (bounceType == BounceType.HARD_BOUNCE) {
      handleHardBounce(tracking.getRecipientEmail(), reason);
    }
  }

  private void handleHardBounce(String email, String reason) {
    log.warn("Hard bounce for {}: {}", email, reason);

    // Mark email as invalid
    userRepository.findByEmail(email).ifPresent(user -> {
      user.setEmailValid(false);
      user.setEmailBouncedAt(Instant.now());
      userRepository.save(user);
    });

    // Optional: Auto-unsubscribe
    unsubscribeService.unsubscribeAll(email, "Hard bounce: " + reason);
  }

  public EmailCampaignStats getCampaignStats(String templateName, Instant since) {
    List<EmailTracking> emails = trackingRepository
      .findByTemplateNameAndSentAtAfter(templateName, since);

    long sent = emails.size();
    long delivered = emails.stream()
      .filter(e -> e.getStatus() == EmailStatus.DELIVERED || e.getOpenedAt() != null)
      .count();
    long opened = emails.stream()
      .filter(e -> e.getOpenedAt() != null)
      .count();
    long clicked = emails.stream()
      .filter(e -> e.getFirstClickedAt() != null)
      .count();
    long bounced = emails.stream()
      .filter(e -> e.getStatus() == EmailStatus.BOUNCED)
      .count();

    return EmailCampaignStats.builder()
      .sent(sent)
      .delivered(delivered)
      .deliveryRate((double) delivered / sent * 100)
      .opened(opened)
      .openRate((double) opened / delivered * 100)
      .clicked(clicked)
      .clickRate((double) clicked / delivered * 100)
      .bounced(bounced)
      .bounceRate((double) bounced / sent * 100)
      .build();
  }
}
```

**3. Tracking pixel (open tracking):**
```java
@Controller
@RequestMapping("/track")
@RequiredArgsConstructor
public class EmailTrackingController {

  private final EmailTrackingService trackingService;

  @GetMapping("/open/{trackingId}")
  public ResponseEntity<byte[]> trackOpen(
    @PathVariable String trackingId,
    HttpServletRequest request
  ) {
    String userAgent = request.getHeader("User-Agent");
    String ipAddress = getClientIp(request);

    try {
      trackingService.trackOpen(trackingId, userAgent, ipAddress);
    } catch (Exception e) {
      log.error("Failed to track email open", e);
    }

    // Return 1x1 transparent GIF
    byte[] pixel = Base64.getDecoder().decode(
      "R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7"
    );

    return ResponseEntity.ok()
      .contentType(MediaType.IMAGE_GIF)
      .cacheControl(CacheControl.noCache())
      .body(pixel);
  }

  @GetMapping("/click/{trackingId}")
  public ResponseEntity<Void> trackClick(
    @PathVariable String trackingId,
    @RequestParam String url
  ) {
    try {
      trackingService.trackClick(trackingId, url);
    } catch (Exception e) {
      log.error("Failed to track email click", e);
    }

    return ResponseEntity.status(HttpStatus.FOUND)
      .location(URI.create(url))
      .build();
  }

  private String getClientIp(HttpServletRequest request) {
    String ip = request.getHeader("X-Forwarded-For");
    if (ip == null || ip.isEmpty()) {
      ip = request.getRemoteAddr();
    }
    return ip;
  }
}
```

**4. Email service với tracking:**
```java
@Service
@RequiredArgsConstructor
public class EmailService {

  private final JavaMailSender mailSender;
  private final SpringTemplateEngine templateEngine;
  private final EmailTrackingService trackingService;

  public void sendTrackedEmail(User user, String templateName, Map<String, Object> variables) {
    String messageId = UUID.randomUUID().toString() + "@example.com";

    // Add tracking pixel and links
    String trackingPixelUrl = "https://example.com/track/open/" + messageId;
    variables.put("trackingPixelUrl", trackingPixelUrl);
    variables.put("trackingId", messageId);

    String html = templateEngine.process(templateName, createContext(variables));

    // Wrap links with click tracking
    html = wrapLinksWithTracking(html, messageId);

    MimeMessage message = mailSender.createMimeMessage();
    try {
      MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");
      helper.setTo(user.getEmail());
      helper.setSubject((String) variables.get("subject"));
      helper.setText(html, true);
      helper.setFrom("noreply@example.com");

      // Set custom Message-ID
      message.setHeader("Message-ID", messageId);

      mailSender.send(message);

      // Create tracking record
      trackingService.createTracking(message, templateName);

    } catch (MessagingException e) {
      throw new EmailSendException("Failed to send tracked email", e);
    }
  }

  private String wrapLinksWithTracking(String html, String trackingId) {
    Document doc = Jsoup.parse(html);

    doc.select("a[href]").forEach(link -> {
      String originalUrl = link.attr("href");

      // Skip tracking pixel and internal links
      if (originalUrl.contains("/track/") || originalUrl.startsWith("#")) {
        return;
      }

      String trackedUrl = "https://example.com/track/click/" + trackingId +
                          "?url=" + URLEncoder.encode(originalUrl, StandardCharsets.UTF_8);
      link.attr("href", trackedUrl);
    });

    return doc.html();
  }

  private Context createContext(Map<String, Object> variables) {
    Context context = new Context();
    context.setVariables(variables);
    return context;
  }
}
```

**5. Email template với tracking pixel:**
```html
<!DOCTYPE html>
<html xmlns:th="http://www.thymeleaf.org">
<head>
  <meta charset="UTF-8">
  <title th:text="${subject}">Email</title>
</head>
<body>
  <div class="content">
    <p th:text="${message}">Message content</p>

    <p>
      <a th:href="@{${ctaUrl}}" th:text="${ctaText}">
        Click here
      </a>
    </p>
  </div>

  <!-- Tracking pixel (invisible 1x1 image) -->
  <img th:src="@{${trackingPixelUrl}}"
       width="1"
       height="1"
       style="display:none;"
       alt="">
</body>
</html>
```

**6. Bounce handling (webhook):**
```java
@RestController
@RequestMapping("/webhooks/email")
@RequiredArgsConstructor
@Slf4j
public class EmailWebhookController {

  private final EmailTrackingService trackingService;

  // SendGrid webhook example
  @PostMapping("/sendgrid")
  public ResponseEntity<Void> handleSendGridWebhook(@RequestBody List<SendGridEvent> events) {
    events.forEach(event -> {
      switch (event.getEvent()) {
        case "delivered" -> trackingService.trackDelivery(event.getMessageId());
        case "bounce" -> trackingService.trackBounce(
          event.getMessageId(),
          event.getType().equals("hard_bounce") ? BounceType.HARD_BOUNCE : BounceType.SOFT_BOUNCE,
          event.getReason()
        );
        case "open" -> trackingService.trackOpen(
          event.getMessageId(),
          event.getUserAgent(),
          event.getIp()
        );
        case "click" -> trackingService.trackClick(
          event.getMessageId(),
          event.getUrl()
        );
        case "spamreport" -> trackingService.trackBounce(
          event.getMessageId(),
          BounceType.COMPLAINT,
          "Marked as spam"
        );
      }
    });

    return ResponseEntity.ok().build();
  }
}

record SendGridEvent(
  String event,
  String email,
  String messageId,
  String type,
  String reason,
  String url,
  String userAgent,
  String ip,
  Instant timestamp
) {}
```

### ❌ Cách sai

```java
// ❌ 1. Không track email delivery
public void sendEmail(User user) {
  mailSender.send(createMessage(user));
  // Không biết email có đến user không
}

// ❌ 2. Tracking pixel block email rendering
<img src="https://example.com/track/open/123" width="100" height="100">
<!-- User nhìn thấy broken image -->

// ❌ 3. Không handle bounces
// Email addresses vẫn gửi mãi dù đã bounce nhiều lần

// ❌ 4. Track mọi email (kể cả transactional)
public void sendPasswordReset(User user) {
  // ❌ Privacy issue: tracking password reset email opens
  sendTrackedEmail(user, "password-reset");
}

// ❌ 5. Không có retry cho tracking failures
@GetMapping("/track/open/{id}")
public void trackOpen(@PathVariable String id) {
  trackingService.trackOpen(id);
  // Nếu tracking fails, exception = broken pixel
}
```

### Phát hiện

**Regex patterns:**
```regex
# Email template không có tracking pixel
<body>(?!.*<img.*track).*</body>

# Send email không create tracking record
mailSender\.send\((?!.*trackingService)
```

**Monitoring query:**
```sql
-- Bounce rate cao (> 5%)
SELECT
  template_name,
  COUNT(*) as total,
  SUM(CASE WHEN status = 'BOUNCED' THEN 1 ELSE 0 END) as bounced,
  SUM(CASE WHEN status = 'BOUNCED' THEN 1 ELSE 0 END) * 100.0 / COUNT(*) as bounce_rate
FROM email_tracking
WHERE sent_at > NOW() - INTERVAL '7 days'
GROUP BY template_name
HAVING bounce_rate > 5;
```

### Checklist

- [ ] `EmailTracking` entity với `messageId`, `openedAt`, `clickedAt`
- [ ] Tracking pixel (1x1 transparent GIF) trong email template
- [ ] Click tracking wrap all links
- [ ] `trackOpen()` và `trackClick()` methods
- [ ] Bounce webhook handler (SendGrid/SES/Mailgun)
- [ ] Hard bounce auto-unsubscribe
- [ ] Campaign stats dashboard (open rate, click rate, bounce rate)
- [ ] Privacy policy disclosure (tracking emails)
- [ ] Opt-out cho tracking (GDPR compliance)
- [ ] Test tracking pixel với real email clients

---

## 18.08 | Rate limiting cho notification endpoints | 🟠 KHUYẾN NGHỊ

### Metadata
- **ID:** `NOTIFICATION_RATE_LIMIT`
- **Mức độ:** 🟠 KHUYẾN NGHỊ
- **Lý do:** DoS prevention, resource protection, spam prevention

### Tại sao?

**Attack scenarios:**
```java
// ❌ Attacker spam notification endpoint
POST /api/notifications/send-to-all
// Gửi 1000 requests = 1M emails

POST /api/users/123/send-notification
// Loop 10,000 requests = spam user's inbox
```

**Rate limiting benefits:**
- ✅ Prevent DoS attacks
- ✅ Protect SMTP server from overload
- ✅ Fair resource allocation per user
- ✅ Prevent accidental infinite loops

### ✅ Cách đúng

**1. Dependencies:**
```xml
<dependency>
  <groupId>com.bucket4j</groupId>
  <artifactId>bucket4j-core</artifactId>
  <version>8.7.0</version>
</dependency>

<dependency>
  <groupId>io.github.bucket4j</groupId>
  <artifactId>bucket4j-redis</artifactId>
  <version>8.7.0</version>
</dependency>
```

**2. Rate limiting configuration:**
```java
@Configuration
public class RateLimitConfig {

  @Bean
  public RateLimiter emailRateLimiter() {
    // 10 emails per minute per user
    Bandwidth limit = Bandwidth.builder()
      .capacity(10)
      .refillGreedy(10, Duration.ofMinutes(1))
      .build();

    return RateLimiter.builder()
      .addLimit(limit)
      .build();
  }

  @Bean
  public RateLimiter bulkEmailRateLimiter() {
    // 1 bulk campaign per hour per user
    Bandwidth limit = Bandwidth.builder()
      .capacity(1)
      .refillGreedy(1, Duration.ofHours(1))
      .build();

    return RateLimiter.builder()
      .addLimit(limit)
      .build();
  }
}
```

**3. Rate limiting interceptor:**
```java
@Component
@RequiredArgsConstructor
@Slf4j
public class RateLimitInterceptor implements HandlerInterceptor {

  private final RedisTemplate<String, String> redisTemplate;
  private static final String RATE_LIMIT_PREFIX = "rate_limit:";

  @Override
  public boolean preHandle(
    HttpServletRequest request,
    HttpServletResponse response,
    Object handler
  ) throws Exception {
    if (!(handler instanceof HandlerMethod handlerMethod)) {
      return true;
    }

    RateLimited annotation = handlerMethod.getMethodAnnotation(RateLimited.class);
    if (annotation == null) {
      return true;
    }

    String key = buildKey(request, annotation);
    int limit = annotation.limit();
    Duration window = Duration.ofSeconds(annotation.windowSeconds());

    if (!checkRateLimit(key, limit, window)) {
      response.setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
      response.setContentType("application/json");
      response.getWriter().write("""
        {
          "error": "Rate limit exceeded",
          "retryAfter": %d
        }
        """.formatted(window.getSeconds()));
      return false;
    }

    return true;
  }

  private String buildKey(HttpServletRequest request, RateLimited annotation) {
    String userId = getCurrentUserId(request);
    String endpoint = request.getRequestURI();
    return RATE_LIMIT_PREFIX + annotation.scope() + ":" + userId + ":" + endpoint;
  }

  private boolean checkRateLimit(String key, int limit, Duration window) {
    String currentCount = redisTemplate.opsForValue().get(key);

    if (currentCount == null) {
      redisTemplate.opsForValue().set(key, "1", window);
      return true;
    }

    int count = Integer.parseInt(currentCount);
    if (count >= limit) {
      return false;
    }

    redisTemplate.opsForValue().increment(key);
    return true;
  }

  private String getCurrentUserId(HttpServletRequest request) {
    // Extract from JWT or session
    return "user-123";
  }
}

@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
public @interface RateLimited {
  int limit() default 10;
  int windowSeconds() default 60;
  String scope() default "user";
}
```

**4. Controller với rate limiting:**
```java
@RestController
@RequestMapping("/api/notifications")
@RequiredArgsConstructor
public class NotificationController {

  private final EmailService emailService;
  private final NotificationService notificationService;

  @PostMapping("/send")
  @RateLimited(limit = 10, windowSeconds = 60) // 10 requests per minute
  public ResponseEntity<NotificationResponse> sendNotification(
    @Valid @RequestBody SendNotificationRequest request,
    @AuthenticationPrincipal UserPrincipal currentUser
  ) {
    emailService.sendNotificationAsync(currentUser, request);

    return ResponseEntity.accepted()
      .body(NotificationResponse.builder()
        .message("Notification queued")
        .build());
  }

  @PostMapping("/bulk")
  @RateLimited(limit = 1, windowSeconds = 3600) // 1 request per hour
  @PreAuthorize("hasRole('ADMIN')")
  public ResponseEntity<BulkNotificationResponse> sendBulkNotification(
    @Valid @RequestBody BulkNotificationRequest request
  ) {
    int queuedCount = notificationService.enqueueBulk(request);

    return ResponseEntity.accepted()
      .body(BulkNotificationResponse.builder()
        .message("Bulk notification queued")
        .recipientCount(queuedCount)
        .build());
  }

  @PostMapping("/users/{userId}/notify")
  @RateLimited(limit = 5, windowSeconds = 300) // 5 per 5 minutes
  public ResponseEntity<Void> notifyUser(
    @PathVariable Long userId,
    @Valid @RequestBody NotifyUserRequest request
  ) {
    User user = userService.findById(userId);
    notificationService.sendToUser(user, request);

    return ResponseEntity.accepted().build();
  }
}
```

**5. Bucket4j rate limiting (advanced):**
```java
@Service
@RequiredArgsConstructor
public class RateLimitService {

  private final ProxyManager<String> proxyManager;

  public boolean tryConsume(String key, RateLimitConfig config) {
    Bucket bucket = proxyManager.builder()
      .build(key, () -> createBucketConfiguration(config));

    return bucket.tryConsume(1);
  }

  public long getRemainingTokens(String key, RateLimitConfig config) {
    Bucket bucket = proxyManager.builder()
      .build(key, () -> createBucketConfiguration(config));

    return bucket.getAvailableTokens();
  }

  private BucketConfiguration createBucketConfiguration(RateLimitConfig config) {
    return BucketConfiguration.builder()
      .addLimit(Bandwidth.builder()
        .capacity(config.getCapacity())
        .refillGreedy(
          config.getRefillTokens(),
          Duration.ofSeconds(config.getRefillSeconds())
        )
        .build())
      .build();
  }
}

@Data
@Builder
public class RateLimitConfig {
  private long capacity;
  private long refillTokens;
  private long refillSeconds;

  public static RateLimitConfig perMinute(int requests) {
    return RateLimitConfig.builder()
      .capacity(requests)
      .refillTokens(requests)
      .refillSeconds(60)
      .build();
  }

  public static RateLimitConfig perHour(int requests) {
    return RateLimitConfig.builder()
      .capacity(requests)
      .refillTokens(requests)
      .refillSeconds(3600)
      .build();
  }
}
```

**6. Service với rate limit check:**
```java
@Service
@RequiredArgsConstructor
@Slf4j
public class NotificationService {

  private final RateLimitService rateLimitService;
  private final EmailQueueService emailQueueService;

  public void sendNotification(User user, NotificationRequest request) {
    String key = "notification:user:" + user.getId();
    RateLimitConfig config = RateLimitConfig.perMinute(10);

    if (!rateLimitService.tryConsume(key, config)) {
      long remaining = rateLimitService.getRemainingTokens(key, config);
      throw new RateLimitExceededException(
        "Notification rate limit exceeded. Remaining: " + remaining
      );
    }

    emailQueueService.enqueue(EmailQueueRequest.builder()
      .recipientEmail(user.getEmail())
      .subject(request.getSubject())
      .templateName(request.getTemplateName())
      .priority(EmailPriority.NORMAL)
      .build());
  }

  public int enqueueBulk(BulkNotificationRequest request) {
    String key = "notification:bulk:" + request.getCampaignId();
    RateLimitConfig config = RateLimitConfig.perHour(1);

    if (!rateLimitService.tryConsume(key, config)) {
      throw new RateLimitExceededException(
        "Bulk notification rate limit exceeded. Please wait 1 hour."
      );
    }

    List<EmailQueue> emails = emailQueueService.enqueueBulk(request);
    return emails.size();
  }
}
```

**7. Global rate limiter (IP-based):**
```java
@Component
@RequiredArgsConstructor
@Order(Ordered.HIGHEST_PRECEDENCE)
public class IpRateLimitFilter extends OncePerRequestFilter {

  private final RateLimitService rateLimitService;

  @Override
  protected void doFilterInternal(
    HttpServletRequest request,
    HttpServletResponse response,
    FilterChain filterChain
  ) throws ServletException, IOException {
    String ip = getClientIp(request);
    String key = "global:ip:" + ip;
    RateLimitConfig config = RateLimitConfig.perMinute(100);

    if (!rateLimitService.tryConsume(key, config)) {
      response.setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
      response.setContentType("application/json");
      response.getWriter().write("""
        {
          "error": "Too many requests from this IP",
          "retryAfter": 60
        }
        """);
      return;
    }

    filterChain.doFilter(request, response);
  }

  private String getClientIp(HttpServletRequest request) {
    String ip = request.getHeader("X-Forwarded-For");
    if (ip == null || ip.isEmpty()) {
      ip = request.getRemoteAddr();
    }
    return ip;
  }
}
```

### ❌ Cách sai

```java
// ❌ 1. Không có rate limiting
@PostMapping("/send-notification")
public void sendNotification(@RequestBody NotificationRequest request) {
  // Attacker có thể spam unlimited requests
  emailService.send(request);
}

// ❌ 2. Rate limit trong memory (không scale)
@RestController
public class BadController {
  private final Map<String, Integer> requestCounts = new ConcurrentHashMap<>();

  @PostMapping("/notify")
  public void notify() {
    // ❌ Không work với multiple instances
    // ❌ Không có expiration = memory leak
    requestCounts.merge("user-123", 1, Integer::sum);
  }
}

// ❌ 3. Fixed rate limit cho tất cả users
// VIP users và normal users bị limit giống nhau

// ❌ 4. Không có retry-after header
@ResponseStatus(HttpStatus.TOO_MANY_REQUESTS)
public class RateLimitException extends RuntimeException {
  // Client không biết bao giờ retry được
}

// ❌ 5. Rate limit chỉ dựa vào userId
String key = "rate_limit:" + userId;
// Attacker tạo nhiều accounts để bypass
```

### Phát hiện

**Regex patterns:**
```regex
# Notification endpoint không có rate limit
@PostMapping.*notification.*\n.*public.*\{(?!.*rateLimitService)

# Không có @RateLimited annotation
@PostMapping.*send.*\)(?!.*@RateLimited)
```

**Load testing:**
```bash
# Kiểm tra rate limit với ab (Apache Bench)
ab -n 1000 -c 10 -H "Authorization: Bearer $TOKEN" \
  https://api.example.com/api/notifications/send

# Expected: Một số requests trả về 429 Too Many Requests
```

### Checklist

- [ ] Bucket4j hoặc Redis-based rate limiter
- [ ] `@RateLimited` annotation cho notification endpoints
- [ ] Different limits cho different endpoint types (individual vs bulk)
- [ ] `429 Too Many Requests` với `Retry-After` header
- [ ] User-based và IP-based rate limiting
- [ ] VIP users có higher limits
- [ ] Rate limit metrics tracking (Prometheus)
- [ ] Admin dashboard xem rate limit violations
- [ ] Alert khi có user hit rate limit nhiều lần (potential attack)
- [ ] Test rate limiting với load testing tools

---

## Tóm tắt

| Practice | Mức độ | Điểm chính |
|----------|--------|-----------|
| 18.01 Template engine | 🟠 KHUYẾN NGHỊ | Thymeleaf, i18n, maintainability |
| 18.02 Async sending | 🔴 BẮT BUỘC | `@Async`, CompletableFuture, không block request |
| 18.03 Retry mechanism | 🟠 KHUYẾN NGHỊ | `@Retryable`, exponential backoff, `@Recover` |
| 18.04 Email queue | 🟠 KHUYẾN NGHỊ | `EmailQueue` entity, priority-based, batch processing |
| 18.05 XSS prevention | 🔴 BẮT BUỘC | Jsoup sanitization, whitelist, validate URLs |
| 18.06 Unsubscribe | 🟡 NÊN CÓ | CAN-SPAM compliance, `List-Unsubscribe` header, one-click |
| 18.07 Delivery tracking | 🟡 NÊN CÓ | Tracking pixel, bounce handling, campaign stats |
| 18.08 Rate limiting | 🟠 KHUYẾN NGHỊ | Bucket4j, Redis, `@RateLimited`, DoS prevention |

**Workflow tích hợp:**
1. User action → Controller validates input
2. Sanitize user content (XSS prevention)
3. Check subscription status (unsubscribe compliance)
4. Check rate limit (DoS prevention)
5. Enqueue email (queue-based processing)
6. Async worker sends email (with retry)
7. Track delivery (opens, clicks, bounces)
8. Handle bounces (auto-unsubscribe hard bounces)

**Production checklist:**
- [ ] All 8 practices implemented
- [ ] Email template preview tool
- [ ] Monitoring dashboard (queue size, delivery rate, bounce rate)
- [ ] Bounce webhook configured (SendGrid/SES/Mailgun)
- [ ] Privacy policy updated (tracking disclosure)
- [ ] Load testing cho bulk campaigns
- [ ] Disaster recovery plan (email queue backup)
