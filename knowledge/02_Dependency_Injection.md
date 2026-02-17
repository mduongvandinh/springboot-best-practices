# Domain 02: Dependency Injection & IoC
> **Số practices:** 9 | 🔴 2 | 🟠 5 | 🟡 2
> **Trọng số:** ×1

---

## 02.01 — Constructor injection thay field injection (@Autowired)

### Metadata
- **Mã số:** 02.01
- **Mức độ:** 🔴 BẮT BUỘC
- **Điểm trừ:** -10
- **Tags:** `dependency-injection`, `testability`, `immutability`, `final-fields`

### Tại sao?
Constructor injection đảm bảo dependencies luôn được khởi tạo đầy đủ, cho phép sử dụng `final` fields (immutability), dễ viết unit test (không cần reflection), và phát hiện circular dependency sớm hơn. Field injection vi phạm nguyên tắc immutability, khó test (phải dùng reflection), và che giấu vấn đề thiết kế khi class có quá nhiều dependencies. Constructor injection cũng tuân thủ nguyên tắc Dependency Inversion (SOLID).

### ✅ Cách đúng
```java
import org.springframework.stereotype.Service;

@Service
public class DoctorService {
  private final DoctorRepository doctorRepository;
  private final NotificationService notificationService;
  private final AuditLogger auditLogger;

  // Constructor injection - Spring tự động inject nếu chỉ có 1 constructor
  public DoctorService(
      DoctorRepository doctorRepository,
      NotificationService notificationService,
      AuditLogger auditLogger) {
    this.doctorRepository = doctorRepository;
    this.notificationService = notificationService;
    this.auditLogger = auditLogger;
  }

  public Doctor findById(Long id) {
    Doctor doctor = doctorRepository.findById(id)
        .orElseThrow(() -> new EntityNotFoundException("Doctor not found"));
    auditLogger.log("Doctor accessed: " + id);
    return doctor;
  }

  public void notifyAvailability(Long doctorId) {
    Doctor doctor = findById(doctorId);
    notificationService.send(doctor.getEmail(), "Availability updated");
  }
}
```

### ❌ Cách sai
```java
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class DoctorService {
  @Autowired  // ❌ Field injection - không thể dùng final, khó test
  private DoctorRepository doctorRepository;

  @Autowired
  private NotificationService notificationService;

  @Autowired
  private AuditLogger auditLogger;

  // ❌ Không thể đảm bảo dependencies đã được inject
  // ❌ Khó viết unit test (phải dùng ReflectionTestUtils)
  // ❌ Che giấu vấn đề khi class có quá nhiều dependencies
}
```

### Phát hiện
```regex
@Autowired\s+(private|protected|public)\s+\w+  # Field injection với @Autowired
@Inject\s+(private|protected|public)\s+\w+     # Field injection với @Inject
```

### Checklist
- [ ] Tất cả dependencies được inject qua constructor
- [ ] Các dependency fields được khai báo `final`
- [ ] Không sử dụng `@Autowired` trên fields
- [ ] Constructor injection cho phép viết unit test dễ dàng

---

## 02.02 — Sử dụng interface cho dependency (loose coupling)

### Metadata
- **Mã số:** 02.02
- **Mức độ:** 🟠 KHUYẾN NGHỊ
- **Điểm trừ:** -5
- **Tags:** `loose-coupling`, `interface`, `testability`, `maintainability`

### Tại sao?
Inject interface thay vì concrete class giúp giảm coupling, dễ swap implementation (ví dụ: MySQL → PostgreSQL, EmailService → SmsService), dễ mock trong unit test, và tuân thủ Dependency Inversion Principle (SOLID). Khi inject concrete class, code phụ thuộc chặt vào implementation cụ thể, khó thay đổi và test. Interface cũng giúp định nghĩa contract rõ ràng giữa các component.

### ✅ Cách đúng
```java
// Interface định nghĩa contract
public interface NotificationService {
  void send(String recipient, String message);
  boolean isAvailable();
}

// Implementation 1: Email
@Service
@Primary  // Default implementation
public class EmailNotificationService implements NotificationService {
  private final JavaMailSender mailSender;

  public EmailNotificationService(JavaMailSender mailSender) {
    this.mailSender = mailSender;
  }

  @Override
  public void send(String recipient, String message) {
    // Send email logic
  }

  @Override
  public boolean isAvailable() {
    return true;
  }
}

// Implementation 2: SMS
@Service
public class SmsNotificationService implements NotificationService {
  private final SmsGateway smsGateway;

  public SmsNotificationService(SmsGateway smsGateway) {
    this.smsGateway = smsGateway;
  }

  @Override
  public void send(String recipient, String message) {
    // Send SMS logic
  }

  @Override
  public boolean isAvailable() {
    return smsGateway.isConnected();
  }
}

// Consumer inject interface - loose coupling
@Service
public class AppointmentService {
  private final NotificationService notificationService;  // ✅ Interface

  public AppointmentService(NotificationService notificationService) {
    this.notificationService = notificationService;
  }

  public void confirmAppointment(Appointment appointment) {
    notificationService.send(
        appointment.getPatientEmail(),
        "Appointment confirmed"
    );
  }
}
```

### ❌ Cách sai
```java
// ❌ Consumer inject concrete class - tight coupling
@Service
public class AppointmentService {
  private final EmailNotificationService emailService;  // ❌ Concrete class

  public AppointmentService(EmailNotificationService emailService) {
    this.emailService = emailService;
  }

  // ❌ Không thể swap sang SMS mà không sửa code
  // ❌ Khó mock trong test
  // ❌ Vi phạm Dependency Inversion Principle
}
```

### Phát hiện
```regex
private\s+final\s+\w+(Service|Repository|Component)\s+\w+;  # Concrete class dependency (heuristic)
(?<!interface\s)\bpublic\s+\w+\([^)]*\w+(Service|Repository|Component)\s+\w+\)  # Constructor nhận concrete class
```

### Checklist
- [ ] Dependencies được inject qua interface
- [ ] Interface định nghĩa contract rõ ràng
- [ ] Có thể swap implementation mà không sửa consumer code
- [ ] Unit test dễ dàng mock dependencies

---

## 02.03 — Tránh circular dependency

### Metadata
- **Mã số:** 02.03
- **Mức độ:** 🔴 BẮT BUỘC
- **Điểm trừ:** -10
- **Tags:** `circular-dependency`, `design-flaw`, `refactoring`

### Tại sao?
Circular dependency (A → B → A) là dấu hiệu thiết kế sai, gây lỗi khởi tạo bean, khó debug, và vi phạm Single Responsibility Principle. Spring có thể xử lý một số trường hợp bằng proxy nhưng đó là workaround, không phải giải pháp đúng. Circular dependency thường xuất hiện khi trách nhiệm không được phân chia rõ ràng giữa các class. Giải pháp đúng là refactor code: tách interface, tạo mediator service, hoặc sử dụng event-driven architecture.

### ✅ Cách đúng
```java
// ❌ TRƯỚC: Circular dependency
// DoctorService → AppointmentService → DoctorService

// ✅ SAU: Tách logic chung ra service riêng
@Service
public class AvailabilityService {
  private final DoctorRepository doctorRepository;
  private final AppointmentRepository appointmentRepository;

  public AvailabilityService(
      DoctorRepository doctorRepository,
      AppointmentRepository appointmentRepository) {
    this.doctorRepository = doctorRepository;
    this.appointmentRepository = appointmentRepository;
  }

  public boolean isDoctorAvailable(Long doctorId, LocalDateTime time) {
    // Logic kiểm tra availability
    return appointmentRepository.countByDoctorAndTime(doctorId, time) == 0;
  }
}

@Service
public class DoctorService {
  private final DoctorRepository doctorRepository;
  private final AvailabilityService availabilityService;  // ✅ Không circular

  public DoctorService(
      DoctorRepository doctorRepository,
      AvailabilityService availabilityService) {
    this.doctorRepository = doctorRepository;
    this.availabilityService = availabilityService;
  }

  public List<Doctor> findAvailableDoctors(LocalDateTime time) {
    return doctorRepository.findAll().stream()
        .filter(doctor -> availabilityService.isDoctorAvailable(doctor.getId(), time))
        .toList();
  }
}

@Service
public class AppointmentService {
  private final AppointmentRepository appointmentRepository;
  private final AvailabilityService availabilityService;  // ✅ Không circular

  public AppointmentService(
      AppointmentRepository appointmentRepository,
      AvailabilityService availabilityService) {
    this.appointmentRepository = appointmentRepository;
    this.availabilityService = availabilityService;
  }

  public Appointment createAppointment(Long doctorId, LocalDateTime time) {
    if (!availabilityService.isDoctorAvailable(doctorId, time)) {
      throw new IllegalStateException("Doctor not available");
    }
    // Create appointment logic
    return null;
  }
}
```

### ❌ Cách sai
```java
// ❌ Circular dependency: DoctorService → AppointmentService → DoctorService
@Service
public class DoctorService {
  private final AppointmentService appointmentService;  // ❌ A → B

  public DoctorService(AppointmentService appointmentService) {
    this.appointmentService = appointmentService;
  }

  public List<Doctor> findAvailableDoctors() {
    return appointmentService.getDoctorsWithNoAppointments();  // ❌ Gọi B
  }
}

@Service
public class AppointmentService {
  private final DoctorService doctorService;  // ❌ B → A

  public AppointmentService(DoctorService doctorService) {
    this.doctorService = doctorService;
  }

  public List<Doctor> getDoctorsWithNoAppointments() {
    return doctorService.findAll();  // ❌ Gọi lại A → Circular!
  }
}
```

### Phát hiện
```regex
# Spring sẽ throw BeanCurrentlyInCreationException
# Phát hiện thủ công: vẽ dependency graph hoặc dùng IDE
```

### Checklist
- [ ] Không có circular dependency trong application
- [ ] Dependency graph là DAG (Directed Acyclic Graph)
- [ ] Logic chung được tách ra service riêng
- [ ] Cân nhắc event-driven nếu cần giao tiếp 2 chiều

---

## 02.04 — Dùng @Qualifier khi có nhiều bean cùng type

### Metadata
- **Mã số:** 02.04
- **Mức độ:** 🟠 KHUYẾN NGHỊ
- **Điểm trừ:** -5
- **Tags:** `qualifier`, `multiple-beans`, `bean-selection`

### Tại sao?
Khi có nhiều bean cùng type (ví dụ: EmailService, SmsService đều implement NotificationService), Spring không biết inject bean nào và sẽ throw `NoUniqueBeanDefinitionException`. `@Qualifier` giúp chỉ định rõ bean nào cần inject. Alternative: dùng `@Primary` cho default bean, hoặc inject `List<Interface>` nếu cần tất cả implementations. `@Qualifier` nên được sử dụng kết hợp với custom annotation để tăng type-safety.

### ✅ Cách đúng
```java
// Define custom qualifiers (type-safe)
@Target({ElementType.FIELD, ElementType.PARAMETER, ElementType.METHOD})
@Retention(RetentionPolicy.RUNTIME)
@Qualifier
public @interface Email {}

@Target({ElementType.FIELD, ElementType.PARAMETER, ElementType.METHOD})
@Retention(RetentionPolicy.RUNTIME)
@Qualifier
public @interface Sms {}

// Implementations với custom qualifiers
@Service
@Email
public class EmailNotificationService implements NotificationService {
  @Override
  public void send(String recipient, String message) {
    // Email logic
  }
}

@Service
@Sms
public class SmsNotificationService implements NotificationService {
  @Override
  public void send(String recipient, String message) {
    // SMS logic
  }
}

// Consumer sử dụng qualifier
@Service
public class AppointmentService {
  private final NotificationService emailService;
  private final NotificationService smsService;

  public AppointmentService(
      @Email NotificationService emailService,
      @Sms NotificationService smsService) {
    this.emailService = emailService;
    this.smsService = smsService;
  }

  public void confirmAppointment(Appointment appointment) {
    emailService.send(appointment.getPatientEmail(), "Confirmed");
    smsService.send(appointment.getPatientPhone(), "Confirmed");
  }
}

// Alternative: Inject tất cả implementations
@Service
public class MultiChannelNotifier {
  private final List<NotificationService> notificationServices;

  public MultiChannelNotifier(List<NotificationService> notificationServices) {
    this.notificationServices = notificationServices;
  }

  public void notifyAll(String recipient, String message) {
    notificationServices.forEach(service -> service.send(recipient, message));
  }
}
```

### ❌ Cách sai
```java
// ❌ Không chỉ định qualifier khi có nhiều bean cùng type
@Service
public class AppointmentService {
  private final NotificationService notificationService;

  public AppointmentService(NotificationService notificationService) {
    // ❌ Spring throw NoUniqueBeanDefinitionException
    // Không biết inject EmailNotificationService hay SmsNotificationService
    this.notificationService = notificationService;
  }
}

// ❌ Sử dụng string-based qualifier (không type-safe)
@Service
public class AppointmentService {
  private final NotificationService emailService;

  public AppointmentService(
      @Qualifier("emailNotificationService") NotificationService emailService) {
    // ❌ String literal - dễ typo, không compile-time safety
    this.emailService = emailService;
  }
}
```

### Phát hiện
```regex
@Qualifier\s*\(\s*"[^"]+"\s*\)  # String-based qualifier (nên dùng custom annotation)
# NoUniqueBeanDefinitionException trong logs
```

### Checklist
- [ ] Sử dụng custom qualifier annotations thay vì string literals
- [ ] Mỗi bean có qualifier rõ ràng hoặc được đánh dấu `@Primary`
- [ ] Inject `List<Interface>` nếu cần tất cả implementations
- [ ] Tránh `NoUniqueBeanDefinitionException`

---

## 02.05 — Bean scope phù hợp (singleton vs prototype vs request)

### Metadata
- **Mã số:** 02.05
- **Mức độ:** 🟠 KHUYẾN NGHỊ
- **Điểm trừ:** -5
- **Tags:** `bean-scope`, `singleton`, `prototype`, `request`, `thread-safety`

### Tại sao?
Mặc định Spring beans là `singleton` (1 instance cho toàn app) - phù hợp cho stateless services. Sử dụng scope sai gây memory leak (prototype bean giữ state), thread-safety issues (singleton bean có mutable state), hoặc lãng phí memory (tạo quá nhiều instance không cần thiết). `@RequestScope` phù hợp cho web beans cần request-specific data. `@Prototype` chỉ dùng khi thực sự cần instance mới mỗi lần inject.

### ✅ Cách đúng
```java
// ✅ Singleton (default) - Stateless service
@Service  // Mặc định @Scope("singleton")
public class DoctorService {
  private final DoctorRepository repository;  // ✅ Stateless, thread-safe

  public DoctorService(DoctorRepository repository) {
    this.repository = repository;
  }

  public Doctor findById(Long id) {
    return repository.findById(id).orElseThrow();
  }
}

// ✅ Request scope - Web beans với request-specific data
@Component
@RequestScope  // Tạo instance mới cho mỗi HTTP request
public class RequestContext {
  private String realm;  // USER, CLINIC, OPERATOR
  private Long userId;
  private String sessionId;

  // Getters/setters - an toàn vì mỗi request có instance riêng
  public void setRealm(String realm) {
    this.realm = realm;
  }

  public String getRealm() {
    return realm;
  }
}

// ✅ Prototype scope - Stateful beans cần instance mới
@Component
@Scope("prototype")
public class AppointmentBuilder {
  private Long doctorId;
  private Long patientId;
  private LocalDateTime scheduledTime;
  private String notes;

  // Builder pattern - mỗi lần build cần instance mới
  public AppointmentBuilder withDoctor(Long doctorId) {
    this.doctorId = doctorId;
    return this;
  }

  public AppointmentBuilder withPatient(Long patientId) {
    this.patientId = patientId;
    return this;
  }

  public Appointment build() {
    return new Appointment(doctorId, patientId, scheduledTime, notes);
  }
}

// Consumer inject prototype bean
@Service
public class AppointmentService {
  private final ObjectProvider<AppointmentBuilder> builderProvider;

  public AppointmentService(ObjectProvider<AppointmentBuilder> builderProvider) {
    this.builderProvider = builderProvider;  // ✅ ObjectProvider cho prototype
  }

  public Appointment createAppointment(Long doctorId, Long patientId) {
    AppointmentBuilder builder = builderProvider.getObject();  // ✅ Instance mới
    return builder.withDoctor(doctorId)
        .withPatient(patientId)
        .build();
  }
}
```

### ❌ Cách sai
```java
// ❌ Singleton bean với mutable state - KHÔNG thread-safe
@Service
public class AppointmentService {
  private Appointment currentAppointment;  // ❌ Mutable state trong singleton!

  public void processAppointment(Appointment appointment) {
    this.currentAppointment = appointment;  // ❌ Race condition!
    // Multiple threads có thể ghi đè lẫn nhau
  }
}

// ❌ Prototype bean không được inject đúng cách
@Service
public class DoctorService {
  private final AppointmentBuilder builder;  // ❌ Inject trực tiếp prototype

  public DoctorService(AppointmentBuilder builder) {
    this.builder = builder;  // ❌ Chỉ tạo 1 instance, không phải prototype!
  }

  public Appointment createAppointment() {
    return builder.build();  // ❌ Dùng lại instance cũ, không tạo mới
  }
}
```

### Phát hiện
```regex
@Service.*\n.*private\s+(?!final)\w+\s+\w+;  # Non-final field trong singleton service (mutable state)
@Scope\s*\(\s*"prototype"\s*\).*\n.*public\s+\w+\([^)]*AppointmentBuilder  # Inject prototype không qua ObjectProvider
```

### Checklist
- [ ] Singleton beans là stateless (không có mutable instance fields)
- [ ] Request-scoped beans dùng `@RequestScope` cho request-specific data
- [ ] Prototype beans inject qua `ObjectProvider<T>` hoặc `Provider<T>`
- [ ] Không lưu state trong singleton beans

---

## 02.06 — Tránh @PostConstruct phức tạp, dùng ApplicationRunner

### Metadata
- **Mã số:** 02.06
- **Mức độ:** 🟡 NÊN CÓ
- **Điểm trừ:** -2
- **Tags:** `initialization`, `post-construct`, `application-runner`, `startup`

### Tại sao?
`@PostConstruct` chạy trong quá trình khởi tạo bean, trước khi context hoàn tất. Nếu logic phức tạp (gọi DB, external API, heavy computation), sẽ làm chậm startup và khó debug khi lỗi. `@PostConstruct` cũng không nhận command-line arguments và không đảm bảo thứ tự khởi tạo. `ApplicationRunner` chạy sau khi context hoàn tất, có thể inject đầy đủ dependencies, nhận arguments, và dễ control execution order với `@Order`.

### ✅ Cách đúng
```java
// ✅ PostConstruct cho logic đơn giản
@Service
public class CacheService {
  private final Map<String, Object> cache = new ConcurrentHashMap<>();

  @PostConstruct
  public void initCache() {
    // ✅ Logic đơn giản, không gọi external resources
    cache.put("initialized", true);
    System.out.println("Cache initialized");
  }
}

// ✅ ApplicationRunner cho logic phức tạp
@Component
@Order(1)  // Chạy đầu tiên
public class DatabaseInitializer implements ApplicationRunner {
  private final DoctorRepository doctorRepository;
  private final ClinicRepository clinicRepository;

  public DatabaseInitializer(
      DoctorRepository doctorRepository,
      ClinicRepository clinicRepository) {
    this.doctorRepository = doctorRepository;
    this.clinicRepository = clinicRepository;
  }

  @Override
  public void run(ApplicationArguments args) throws Exception {
    // ✅ Logic phức tạp: gọi DB, có thể lỗi, cần logging
    if (doctorRepository.count() == 0) {
      System.out.println("Seeding initial doctors...");
      // Seed data logic
    }

    if (clinicRepository.count() == 0) {
      System.out.println("Seeding initial clinics...");
      // Seed data logic
    }

    // ✅ Có thể đọc command-line arguments
    if (args.containsOption("force-seed")) {
      System.out.println("Force seeding enabled");
    }
  }
}

// ✅ ApplicationRunner với conditional execution
@Component
@ConditionalOnProperty(name = "app.cache.warmup.enabled", havingValue = "true")
public class CacheWarmer implements ApplicationRunner {
  private final DoctorService doctorService;

  public CacheWarmer(DoctorService doctorService) {
    this.doctorService = doctorService;
  }

  @Override
  public void run(ApplicationArguments args) throws Exception {
    System.out.println("Warming up cache...");
    doctorService.findAll();  // ✅ Pre-load cache
    System.out.println("Cache warmed up");
  }
}
```

### ❌ Cách sai
```java
// ❌ PostConstruct với logic phức tạp
@Service
public class DoctorService {
  @Autowired
  private DoctorRepository repository;

  @PostConstruct
  public void init() {
    // ❌ Gọi DB trong PostConstruct - chậm startup
    if (repository.count() == 0) {
      // ❌ Logic phức tạp, nếu lỗi khó debug
      repository.save(new Doctor("Default Doctor"));
    }

    // ❌ Gọi external API - có thể timeout, chặn startup
    HttpClient.get("https://api.example.com/doctors");

    // ❌ Heavy computation - làm chậm khởi động
    for (int i = 0; i < 1000000; i++) {
      // Expensive operation
    }
  }
}
```

### Phát hiện
```regex
@PostConstruct\s+public\s+void\s+\w+\(\)\s+\{[^}]{200,}  # PostConstruct method dài hơn 200 chars (heuristic)
@PostConstruct.*\n.*repository\.\w+\(  # PostConstruct gọi repository
@PostConstruct.*\n.*HttpClient  # PostConstruct gọi HTTP client
```

### Checklist
- [ ] `@PostConstruct` chỉ cho logic đơn giản (init collections, logging)
- [ ] Logic phức tạp (DB, API, heavy tasks) dùng `ApplicationRunner`
- [ ] Sử dụng `@Order` để control execution order của runners
- [ ] Startup time nhanh (< 5s cho app nhỏ)

---

## 02.07 — Không inject ApplicationContext trực tiếp

### Metadata
- **Mã số:** 02.07
- **Mức độ:** 🟠 KHUYẾN NGHỊ
- **Điểm trừ:** -5
- **Tags:** `application-context`, `service-locator`, `anti-pattern`, `coupling`

### Tại sao?
Inject `ApplicationContext` biến class thành Service Locator anti-pattern, tăng coupling với Spring framework, khó test (phải mock toàn bộ context), và che giấu dependencies thực sự của class. Khi cần dynamic bean lookup, nên sử dụng `ObjectProvider<T>`, `BeanFactory`, hoặc refactor thiết kế để inject dependencies rõ ràng. ApplicationContext chỉ nên dùng trong infrastructure code (custom framework extensions), không phải business logic.

### ✅ Cách đúng
```java
// ✅ Inject dependencies trực tiếp
@Service
public class AppointmentService {
  private final DoctorRepository doctorRepository;
  private final PatientRepository patientRepository;
  private final NotificationService notificationService;

  public AppointmentService(
      DoctorRepository doctorRepository,
      PatientRepository patientRepository,
      NotificationService notificationService) {
    this.doctorRepository = doctorRepository;
    this.patientRepository = patientRepository;
    this.notificationService = notificationService;
  }

  // ✅ Dependencies rõ ràng, dễ test
}

// ✅ Dùng ObjectProvider cho dynamic bean lookup
@Service
public class NotificationDispatcher {
  private final Map<String, NotificationService> notificationServices;

  public NotificationDispatcher(List<NotificationService> services) {
    // ✅ Inject tất cả implementations, tự build map
    this.notificationServices = services.stream()
        .collect(Collectors.toMap(
            service -> service.getClass().getSimpleName(),
            service -> service
        ));
  }

  public void dispatch(String channel, String message) {
    NotificationService service = notificationServices.get(channel);
    if (service != null) {
      service.send("recipient", message);
    }
  }
}

// ✅ Strategy pattern thay vì lookup từ context
@Service
public class PaymentProcessor {
  private final Map<PaymentMethod, PaymentGateway> gateways;

  public PaymentProcessor(
      @Qualifier("creditCard") PaymentGateway creditCardGateway,
      @Qualifier("bankTransfer") PaymentGateway bankTransferGateway) {
    this.gateways = Map.of(
        PaymentMethod.CREDIT_CARD, creditCardGateway,
        PaymentMethod.BANK_TRANSFER, bankTransferGateway
    );
  }

  public void processPayment(PaymentMethod method, BigDecimal amount) {
    PaymentGateway gateway = gateways.get(method);
    gateway.charge(amount);
  }
}
```

### ❌ Cách sai
```java
// ❌ Inject ApplicationContext - Service Locator anti-pattern
@Service
public class AppointmentService {
  private final ApplicationContext context;  // ❌ Tăng coupling với Spring

  public AppointmentService(ApplicationContext context) {
    this.context = context;
  }

  public void createAppointment(Appointment appointment) {
    // ❌ Lookup bean từ context - dependencies không rõ ràng
    DoctorRepository doctorRepo = context.getBean(DoctorRepository.class);
    Doctor doctor = doctorRepo.findById(appointment.getDoctorId()).orElseThrow();

    // ❌ Khó test - phải mock toàn bộ context
    NotificationService notifier = context.getBean(NotificationService.class);
    notifier.send(doctor.getEmail(), "Appointment created");

    // ❌ Che giấu dependencies, vi phạm Dependency Injection
  }
}

// ❌ Dùng context cho dynamic lookup (nên dùng ObjectProvider)
@Service
public class NotificationDispatcher {
  private final ApplicationContext context;

  public NotificationDispatcher(ApplicationContext context) {
    this.context = context;
  }

  public void dispatch(String beanName, String message) {
    // ❌ Runtime lookup - không type-safe, dễ lỗi
    NotificationService service = (NotificationService) context.getBean(beanName);
    service.send("recipient", message);
  }
}
```

### Phát hiện
```regex
private\s+final\s+ApplicationContext\s+\w+;  # Field inject ApplicationContext
context\.getBean\(  # Lookup bean từ context trong business logic
```

### Checklist
- [ ] Không inject `ApplicationContext` trong business services
- [ ] Dependencies được inject trực tiếp qua constructor
- [ ] Dùng `ObjectProvider<T>` hoặc `List<T>` cho dynamic lookup
- [ ] Unit tests không cần mock ApplicationContext

---

## 02.08 — Sử dụng @Lazy cho bean khởi tạo nặng

### Metadata
- **Mã số:** 02.08
- **Mức độ:** 🟡 NÊN CÓ
- **Điểm trừ:** -2
- **Tags:** `lazy-loading`, `performance`, `startup-time`, `optimization`

### Tại sao?
Mặc định Spring khởi tạo tất cả singleton beans khi startup. Nếu bean nặng (load file lớn, connect DB, heavy computation) không cần dùng ngay, sẽ làm chậm startup time. `@Lazy` cho phép defer initialization đến khi bean được inject lần đầu. Tuy nhiên, cẩn thận với lazy beans: có thể gây latency khi first access, và lỗi khởi tạo chỉ xuất hiện khi runtime (không phải startup).

### ✅ Cách đúng
```java
// ✅ Eager initialization (default) cho beans thường dùng
@Service
public class DoctorService {
  private final DoctorRepository repository;

  public DoctorService(DoctorRepository repository) {
    this.repository = repository;
  }
  // ✅ Khởi tạo ngay khi startup - fail fast nếu có lỗi
}

// ✅ Lazy initialization cho beans nặng, ít dùng
@Service
@Lazy  // Chỉ khởi tạo khi được inject lần đầu
public class ReportGenerator {
  private final Map<String, Object> heavyTemplates;

  public ReportGenerator() {
    System.out.println("Loading heavy report templates...");
    // ✅ Load file templates lớn (5-10MB)
    this.heavyTemplates = loadTemplatesFromDisk();
  }

  private Map<String, Object> loadTemplatesFromDisk() {
    // Heavy I/O operation
    return Map.of();
  }

  public byte[] generateReport(String templateName, Map<String, Object> data) {
    // Generate report logic
    return new byte[0];
  }
}

// ✅ Lazy inject dependency nặng
@RestController
@RequestMapping("/api/reports")
public class ReportController {
  private final ReportGenerator reportGenerator;

  public ReportController(@Lazy ReportGenerator reportGenerator) {
    // ✅ ReportGenerator chỉ khởi tạo khi endpoint được gọi
    this.reportGenerator = reportGenerator;
  }

  @GetMapping("/monthly")
  public ResponseEntity<byte[]> generateMonthlyReport() {
    // ✅ First call sẽ trigger initialization
    byte[] report = reportGenerator.generateReport("monthly", Map.of());
    return ResponseEntity.ok(report);
  }
}

// ✅ Conditional bean cho features optional
@Configuration
public class FeatureConfig {
  @Bean
  @Lazy
  @ConditionalOnProperty(name = "feature.analytics.enabled", havingValue = "true")
  public AnalyticsService analyticsService() {
    return new AnalyticsService();  // ✅ Chỉ tạo nếu feature enabled
  }
}
```

### ❌ Cách sai
```java
// ❌ Không dùng @Lazy cho bean nặng, ít dùng
@Service
public class ReportGenerator {
  private final Map<String, Object> heavyTemplates;

  public ReportGenerator() {
    // ❌ Load ngay khi startup dù có thể không dùng
    System.out.println("Loading 100MB templates at startup...");
    this.heavyTemplates = loadHugeTemplatesFromDisk();  // ❌ 5-10s delay
  }
  // ❌ Làm chậm startup dù chỉ 10% requests cần reports
}

// ❌ Lạm dụng @Lazy cho mọi bean
@Service
@Lazy  // ❌ Không cần thiết cho service thường dùng
public class DoctorService {
  private final DoctorRepository repository;

  public DoctorService(DoctorRepository repository) {
    this.repository = repository;
  }
  // ❌ Lazy không cần thiết, gây latency first request
  // ❌ Lỗi khởi tạo không được phát hiện sớm
}
```

### Phát hiện
```regex
@Service\s+public\s+class\s+\w+\s+\{[^}]*new\s+File.*\d+MB  # Service load file lớn không có @Lazy (heuristic)
@Bean.*\n.*loadFromDisk\(  # Bean method load file không có @Lazy
```

### Checklist
- [ ] Beans nặng, ít dùng được đánh dấu `@Lazy`
- [ ] Beans thường dùng eager initialization để fail fast
- [ ] Startup time < 5s (app nhỏ) hoặc < 15s (app lớn)
- [ ] Cân nhắc trade-off: startup time vs first-request latency

---

## 02.09 — Profile-specific beans với @Profile

### Metadata
- **Mã số:** 02.09
- **Mức độ:** 🟠 KHUYẾN NGHỊ
- **Điểm trừ:** -5
- **Tags:** `profiles`, `environment`, `configuration`, `dev-prod`

### Tại sao?
Các môi trường khác nhau (dev, staging, production) cần cấu hình khác nhau: dev dùng H2 in-memory DB, prod dùng PostgreSQL; dev enable debug logging, prod disable; dev có thể dùng mock external services. `@Profile` giúp define beans chỉ active trong profile cụ thể, tránh code lẫn lộn giữa các môi trường và giảm rủi ro dùng nhầm config (ví dụ: test DB trên prod).

### ✅ Cách đúng
```java
// ✅ Dev profile - In-memory DB, relaxed security
@Configuration
@Profile("dev")
public class DevConfig {
  @Bean
  public DataSource dataSource() {
    // ✅ H2 in-memory cho dev
    return new EmbeddedDatabaseBuilder()
        .setType(EmbeddedDatabaseType.H2)
        .build();
  }

  @Bean
  public NotificationService notificationService() {
    // ✅ Mock service cho dev - không gửi email thật
    return new MockNotificationService();
  }

  @Bean
  public SecurityConfig securityConfig() {
    // ✅ Relaxed security cho dev
    return new SecurityConfig(false);
  }
}

// ✅ Production profile - Real DB, strict security
@Configuration
@Profile("prod")
public class ProdConfig {
  @Bean
  public DataSource dataSource(
      @Value("${db.url}") String url,
      @Value("${db.username}") String username,
      @Value("${db.password}") String password) {
    // ✅ PostgreSQL cho production
    HikariConfig config = new HikariConfig();
    config.setJdbcUrl(url);
    config.setUsername(username);
    config.setPassword(password);
    return new HikariDataSource(config);
  }

  @Bean
  public NotificationService notificationService() {
    // ✅ Real email service
    return new EmailNotificationService();
  }

  @Bean
  public SecurityConfig securityConfig() {
    // ✅ Strict security cho prod
    return new SecurityConfig(true);
  }
}

// ✅ Component với profile-specific behavior
@Service
@Profile("!prod")  // Active khi KHÔNG phải prod (dev, test, staging)
public class DebugLogger {
  public void logDebugInfo(String message) {
    System.out.println("[DEBUG] " + message);
  }
}

// ✅ Multiple profiles
@Configuration
@Profile({"dev", "staging"})  // Active trong dev HOẶC staging
public class NonProdConfig {
  @Bean
  public DebugTools debugTools() {
    return new DebugTools();
  }
}

// ✅ Programmatic profile check
@Service
public class AppService {
  private final Environment environment;

  public AppService(Environment environment) {
    this.environment = environment;
  }

  public void doSomething() {
    if (environment.acceptsProfiles(Profiles.of("dev"))) {
      // ✅ Dev-specific logic
      System.out.println("Running in dev mode");
    }
  }
}
```

### ❌ Cách sai
```java
// ❌ Không dùng profiles, dùng if-else với hardcoded checks
@Configuration
public class AppConfig {
  @Bean
  public DataSource dataSource() {
    String env = System.getProperty("env");  // ❌ Hardcoded check
    if ("dev".equals(env)) {
      return new EmbeddedDatabaseBuilder().build();
    } else {
      return new HikariDataSource();  // ❌ Không type-safe, dễ lỗi
    }
  }
}

// ❌ Không tách config theo profile
@Service
public class NotificationService {
  public void send(String recipient, String message) {
    if (isProd()) {  // ❌ Logic phân nhánh trong code
      sendRealEmail(recipient, message);
    } else {
      System.out.println("Mock: " + message);  // ❌ Mock code lẫn prod code
    }
  }

  private boolean isProd() {
    return "prod".equals(System.getenv("ENV"));  // ❌ Hardcoded
  }
}

// ❌ Dùng nhầm config giữa các môi trường
@Configuration
public class SingleConfig {
  @Bean
  public DataSource dataSource() {
    // ❌ Luôn dùng H2, kể cả prod!
    return new EmbeddedDatabaseBuilder().build();
  }
}
```

### Phát hiện
```regex
System\.getProperty\("env"\)  # Hardcoded environment check
System\.getenv\("ENV"\)  # Hardcoded environment variable
if\s+\(\s*isProd\(\s*\)  # Manual environment check trong business logic
```

### Checklist
- [ ] Mỗi môi trường (dev, staging, prod) có profile riêng
- [ ] Beans environment-specific dùng `@Profile`
- [ ] Không có hardcoded environment checks trong code
- [ ] Application properties tách theo profile (`application-dev.yml`, `application-prod.yml`)
- [ ] Active profile được set qua `spring.profiles.active` trong deployment
