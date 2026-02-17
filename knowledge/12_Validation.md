# Domain 12: Validation & Data Binding

> **Số practices:** 10 | 🔴 3 | 🟠 5 | 🟡 2
> **Trọng số:** ×1

---

## 12.01 Bean Validation (@NotNull, @Size, @Email) trên DTO

### 🔴 BẮT BUỘC

### Metadata
- **ID:** `VP-12.01`
- **Severity:** CRITICAL
- **Phạm vi:** DTO classes
- **Công cụ:** `jakarta.validation.constraints.*`

### Tại sao?
- **Bảo mật:** Ngăn chặn dữ liệu không hợp lệ vào hệ thống
- **Nhất quán:** Validation logic tập trung, không rải rác
- **Tự động:** Framework tự động kiểm tra, giảm boilerplate code
- **Tài liệu:** Annotations là tài liệu sống cho API
- **Lỗi sớm:** Phát hiện lỗi ở tầng controller, không đến database

### ✅ Cách đúng

```java
// ✅ ĐÚNG: Bean Validation annotations trên tất cả DTO fields
package jp.medicalbox.dto.auth;

import jakarta.validation.constraints.*;
import java.time.LocalDate;

public record RegisterRequest(
  @NotBlank(message = "Email không được để trống")
  @Email(message = "Email không hợp lệ")
  @Size(max = 100, message = "Email tối đa 100 ký tự")
  String email,

  @NotBlank(message = "Mật khẩu không được để trống")
  @Size(min = 8, max = 100, message = "Mật khẩu từ 8-100 ký tự")
  @Pattern(
    regexp = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d).*$",
    message = "Mật khẩu phải có chữ hoa, chữ thường và số"
  )
  String password,

  @NotBlank(message = "Họ tên không được để trống")
  @Size(min = 2, max = 100, message = "Họ tên từ 2-100 ký tự")
  String fullName,

  @Past(message = "Ngày sinh phải là ngày trong quá khứ")
  LocalDate birthDate,

  @Pattern(
    regexp = "^(\\+84|0)[0-9]{9,10}$",
    message = "Số điện thoại không hợp lệ"
  )
  String phoneNumber
) {}

// ✅ ĐÚNG: Controller trigger validation với @Valid
@RestController
@RequestMapping("/api/auth")
@Validated
public class AuthController {

  @PostMapping("/register")
  public ResponseEntity<AuthResponse> register(
    @Valid @RequestBody RegisterRequest request
  ) {
    // Nếu validation fail, Spring tự động throw MethodArgumentNotValidException
    return ResponseEntity.ok(authService.register(request));
  }
}

// ✅ ĐÚNG: Global exception handler cho validation errors
@RestControllerAdvice
public class GlobalExceptionHandler {

  @ExceptionHandler(MethodArgumentNotValidException.class)
  public ResponseEntity<ErrorResponse> handleValidation(
    MethodArgumentNotValidException ex
  ) {
    Map<String, String> errors = new HashMap<>();

    ex.getBindingResult().getFieldErrors().forEach(error ->
      errors.put(error.getField(), error.getDefaultMessage())
    );

    return ResponseEntity
      .status(HttpStatus.BAD_REQUEST)
      .body(new ErrorResponse("VALIDATION_FAILED", errors));
  }
}
```

### ❌ Cách sai

```java
// ❌ SAI: Không có validation annotations
public record RegisterRequest(
  String email,
  String password,
  String fullName
) {}

// ❌ SAI: Manual validation trong service (rải rác, khó maintain)
@Service
public class AuthService {

  public void register(RegisterRequest request) {
    if (request.email() == null || request.email().isBlank()) {
      throw new IllegalArgumentException("Email is required");
    }

    if (!request.email().contains("@")) {
      throw new IllegalArgumentException("Invalid email");
    }

    if (request.password() == null || request.password().length() < 8) {
      throw new IllegalArgumentException("Password too short");
    }

    // Logic rải rác, khó test, không tái sử dụng
  }
}

// ❌ SAI: Thiếu @Valid trong controller
@PostMapping("/register")
public ResponseEntity<?> register(@RequestBody RegisterRequest request) {
  // Validation bị bỏ qua!
  return ResponseEntity.ok(authService.register(request));
}
```

### Phát hiện

```regex
# Tìm DTO classes không có validation annotations
public record \w+Request\([^)]*\) \{
(?!.*@NotNull|@NotBlank|@NotEmpty|@Email|@Size|@Pattern)

# Tìm @RequestBody thiếu @Valid
@RequestBody(?!\s+@Valid)\s+\w+Request

# Tìm manual validation trong service
if\s*\(\s*\w+\s*==\s*null\s*\|\|\s*\w+\.is(Blank|Empty)
```

### Checklist

- [ ] Tất cả DTO request có Bean Validation annotations
- [ ] `@NotNull`, `@NotBlank`, `@NotEmpty` cho required fields
- [ ] `@Size`, `@Min`, `@Max` cho giới hạn độ dài/giá trị
- [ ] `@Email`, `@Pattern` cho format validation
- [ ] `@Valid` trên tất cả `@RequestBody` parameters
- [ ] Custom error messages rõ ràng, i18n ready
- [ ] Global exception handler cho `MethodArgumentNotValidException`
- [ ] Không có manual validation logic trong service

---

## 12.02 Custom validator cho business rules phức tạp

### 🟠 KHUYẾN NGHỊ

### Metadata
- **ID:** `VP-12.02`
- **Severity:** HIGH
- **Phạm vi:** Complex business validation
- **Công cụ:** `@Constraint`, `ConstraintValidator`

### Tại sao?
- **Tái sử dụng:** Business rules phức tạp được đóng gói thành annotation
- **Declarative:** Validation logic gắn ngay trên field, dễ đọc
- **Testable:** Custom validator có thể unit test riêng
- **Cross-field:** Validate nhiều fields cùng lúc (VD: startDate < endDate)
- **Database access:** Có thể inject service để check uniqueness

### ✅ Cách đúng

```java
// ✅ ĐÚNG: Custom annotation cho unique email validation
package jp.medicalbox.validation;

import jakarta.validation.Constraint;
import jakarta.validation.Payload;
import java.lang.annotation.*;

@Documented
@Constraint(validatedBy = UniqueEmailValidator.class)
@Target({ElementType.FIELD, ElementType.PARAMETER})
@Retention(RetentionPolicy.RUNTIME)
public @interface UniqueEmail {

  String message() default "Email đã tồn tại trong hệ thống";

  Class<?>[] groups() default {};

  Class<? extends Payload>[] payload() default {};
}

// ✅ ĐÚNG: Validator implementation với database check
@Component
public class UniqueEmailValidator
  implements ConstraintValidator<UniqueEmail, String> {

  private final UserRepository userRepository;

  public UniqueEmailValidator(UserRepository userRepository) {
    this.userRepository = userRepository;
  }

  @Override
  public boolean isValid(String email, ConstraintValidatorContext context) {
    if (email == null || email.isBlank()) {
      return true; // @NotBlank sẽ handle case này
    }

    return !userRepository.existsByEmail(email);
  }
}

// ✅ ĐÚNG: Sử dụng custom annotation
public record RegisterRequest(
  @NotBlank
  @Email
  @UniqueEmail // Custom validator tự động check DB
  String email,

  @NotBlank
  @Size(min = 8, max = 100)
  String password
) {}

// ✅ ĐÚNG: Cross-field validation annotation
@Documented
@Constraint(validatedBy = DateRangeValidator.class)
@Target({ElementType.TYPE}) // Class-level annotation
@Retention(RetentionPolicy.RUNTIME)
public @interface ValidDateRange {

  String message() default "Ngày kết thúc phải sau ngày bắt đầu";

  Class<?>[] groups() default {};

  Class<? extends Payload>[] payload() default {};

  String startField();

  String endField();
}

// ✅ ĐÚNG: Cross-field validator implementation
public class DateRangeValidator
  implements ConstraintValidator<ValidDateRange, Object> {

  private String startField;
  private String endField;

  @Override
  public void initialize(ValidDateRange annotation) {
    this.startField = annotation.startField();
    this.endField = annotation.endField();
  }

  @Override
  public boolean isValid(Object value, ConstraintValidatorContext context) {
    try {
      var startDate = (LocalDate) BeanUtils
        .getPropertyDescriptor(value.getClass(), startField)
        .getReadMethod()
        .invoke(value);

      var endDate = (LocalDate) BeanUtils
        .getPropertyDescriptor(value.getClass(), endField)
        .getReadMethod()
        .invoke(value);

      if (startDate == null || endDate == null) {
        return true; // Other validators handle null
      }

      return endDate.isAfter(startDate);

    } catch (Exception e) {
      return false;
    }
  }
}

// ✅ ĐÚNG: Sử dụng cross-field validation
@ValidDateRange(startField = "startDate", endField = "endDate")
public record CreateAppointmentRequest(
  @NotNull
  @FutureOrPresent
  LocalDate startDate,

  @NotNull
  @FutureOrPresent
  LocalDate endDate,

  @NotBlank
  String reason
) {}
```

### ❌ Cách sai

```java
// ❌ SAI: Manual validation trong service thay vì custom validator
@Service
public class UserService {

  public void register(RegisterRequest request) {
    // Business rule rải rác, không reusable
    if (userRepository.existsByEmail(request.email())) {
      throw new BusinessException("Email already exists");
    }

    // Không thể test riêng logic này
  }
}

// ❌ SAI: Cross-field validation trong controller
@PostMapping("/appointments")
public ResponseEntity<?> create(@Valid @RequestBody CreateRequest req) {
  if (req.endDate().isBefore(req.startDate())) {
    throw new ValidationException("End date must be after start date");
  }

  // Logic validation không declarative, khó maintain
}

// ❌ SAI: Custom validator không handle null properly
public class UniqueEmailValidator
  implements ConstraintValidator<UniqueEmail, String> {

  @Override
  public boolean isValid(String email, ConstraintValidatorContext context) {
    // ❌ NullPointerException nếu email = null
    return !userRepository.existsByEmail(email);
  }
}
```

### Phát hiện

```regex
# Tìm business validation trong service layer
if\s*\(\s*\w+Repository\.exists

# Tìm cross-field validation trong controller
if\s*\(\s*\w+\.\w+\(\)\.(isBefore|isAfter|compareTo)

# Tìm manual uniqueness checks
throw new \w+Exception\(".*already exists
```

### Checklist

- [ ] Business rules phức tạp dùng custom `@Constraint` annotation
- [ ] Custom validator implement `ConstraintValidator<A, T>`
- [ ] Validator có thể inject dependencies (repositories, services)
- [ ] Validator handle null input correctly (return true)
- [ ] Cross-field validation dùng class-level annotation
- [ ] Custom validators có unit tests riêng
- [ ] Error messages rõ ràng, i18n ready
- [ ] Không có business validation logic trong service/controller

---

## 12.03 Validation groups cho create vs update

### 🟡 NÊN CÓ

### Metadata
- **ID:** `VP-12.03`
- **Severity:** MEDIUM
- **Phạm vi:** DTO với create/update khác nhau
- **Công cụ:** `@Validated`, validation groups

### Tại sao?
- **Khác biệt logic:** Create yêu cầu password, Update không
- **Tái sử dụng DTO:** Một DTO cho cả create và update
- **Linh hoạt:** Bật/tắt constraints theo operation
- **Type-safe:** Compile-time safety thay vì runtime checks

### ✅ Cách đúng

```java
// ✅ ĐÚNG: Define validation groups
package jp.medicalbox.validation;

public interface ValidationGroups {

  interface Create {}

  interface Update {}

  interface PartialUpdate {}
}

// ✅ ĐÚNG: Sử dụng groups trong DTO
package jp.medicalbox.dto.user;

import jp.medicalbox.validation.ValidationGroups.*;

public record UserRequest(
  // ID chỉ required cho Update
  @NotNull(groups = Update.class)
  @Null(groups = Create.class, message = "ID phải null khi tạo mới")
  Long id,

  // Email required cho Create, optional cho Update
  @NotBlank(groups = Create.class)
  @Email(groups = {Create.class, Update.class})
  String email,

  // Password required cho Create, optional cho Update
  @NotBlank(groups = Create.class)
  @Size(min = 8, groups = {Create.class, Update.class})
  String password,

  // Full name required cho cả 2
  @NotBlank(groups = {Create.class, Update.class})
  @Size(min = 2, max = 100, groups = {Create.class, Update.class})
  String fullName,

  // Phone optional cho cả 2
  @Pattern(
    regexp = "^(\\+84|0)[0-9]{9,10}$",
    groups = {Create.class, Update.class}
  )
  String phoneNumber
) {}

// ✅ ĐÚNG: Controller specify validation group
@RestController
@RequestMapping("/api/users")
public class UserController {

  @PostMapping
  public ResponseEntity<UserResponse> create(
    @Validated(Create.class) @RequestBody UserRequest request
  ) {
    // Chỉ validate constraints có groups = Create.class
    return ResponseEntity.ok(userService.create(request));
  }

  @PutMapping("/{id}")
  public ResponseEntity<UserResponse> update(
    @PathVariable Long id,
    @Validated(Update.class) @RequestBody UserRequest request
  ) {
    // Chỉ validate constraints có groups = Update.class
    return ResponseEntity.ok(userService.update(id, request));
  }

  @PatchMapping("/{id}")
  public ResponseEntity<UserResponse> partialUpdate(
    @PathVariable Long id,
    @Validated(PartialUpdate.class) @RequestBody UserRequest request
  ) {
    // Tất cả fields optional
    return ResponseEntity.ok(userService.partialUpdate(id, request));
  }
}

// ✅ ĐÚNG: Default group cho common validations
public record ProductRequest(
  @NotNull(groups = Update.class)
  Long id,

  // Không specify groups = validate cho tất cả operations
  @NotBlank
  @Size(max = 200)
  String name,

  @NotNull
  @Positive
  BigDecimal price
) {}
```

### ❌ Cách sai

```java
// ❌ SAI: Tạo 2 DTO riêng cho Create và Update
public record CreateUserRequest(
  @NotBlank String email,
  @NotBlank String password,
  @NotBlank String fullName
) {}

public record UpdateUserRequest(
  @NotNull Long id,
  String email,      // Nullable
  String password,   // Nullable
  String fullName    // Nullable
) {}
// Duplicate code, khó maintain consistency

// ❌ SAI: Dùng @Valid thay vì @Validated với groups
@PostMapping
public ResponseEntity<?> create(
  @Valid @RequestBody UserRequest request // ❌ @Valid không support groups
) {
  return ResponseEntity.ok(userService.create(request));
}

// ❌ SAI: Manual validation trong service
@Service
public class UserService {

  public void create(UserRequest request) {
    if (request.password() == null) {
      throw new ValidationException("Password required for create");
    }
    // Logic validation nên ở DTO layer
  }

  public void update(Long id, UserRequest request) {
    if (request.id() == null) {
      throw new ValidationException("ID required for update");
    }
    // Duplicate validation logic
  }
}
```

### Phát hiện

```regex
# Tìm duplicate DTOs (CreateXxxRequest + UpdateXxxRequest)
public record Create\w+Request.*\n.*\n.*public record Update\w+Request

# Tìm @Valid thay vì @Validated
@Valid\s+@RequestBody

# Tìm manual operation-specific validation
if.*create.*password.*null
if.*update.*id.*null
```

### Checklist

- [ ] Define `ValidationGroups` interface với `Create`, `Update` subinterfaces
- [ ] Sử dụng `groups` parameter trong validation annotations
- [ ] Controller dùng `@Validated(Group.class)` thay vì `@Valid`
- [ ] Fields required khác nhau giữa create/update có groups khác nhau
- [ ] Common validations không specify groups (validate mọi lúc)
- [ ] Không duplicate DTO cho create/update
- [ ] Không có manual operation-specific validation trong service

---

## 12.04 @Valid trên nested objects

### 🟠 KHUYẾN NGHỊ

### Metadata
- **ID:** `VP-12.04`
- **Severity:** HIGH
- **Phạm vi:** DTO với nested objects/collections
- **Công cụ:** `@Valid`, cascade validation

### Tại sao?
- **Deep validation:** Validate toàn bộ object graph, không chỉ top-level
- **Tránh bug ẩn:** Nested object không hợp lệ có thể bypass validation
- **Consistent:** Mọi level của data đều được validate
- **Rõ ràng:** Explicit declaration về validation behavior

### ✅ Cách đúng

```java
// ✅ ĐÚNG: @Valid trên nested object fields
package jp.medicalbox.dto.appointment;

import jakarta.validation.Valid;
import jakarta.validation.constraints.*;
import java.util.List;

public record CreateAppointmentRequest(
  @NotNull
  @FutureOrPresent
  LocalDateTime appointmentTime,

  @NotBlank
  @Size(max = 500)
  String reason,

  // ✅ @Valid cascade validation vào nested object
  @NotNull
  @Valid
  PatientInfo patient,

  @NotNull
  @Valid
  DoctorInfo doctor,

  // ✅ @Valid cascade validation vào collection elements
  @NotEmpty(message = "Ít nhất 1 dịch vụ")
  @Size(max = 10, message = "Tối đa 10 dịch vụ")
  @Valid
  List<ServiceItem> services
) {}

// ✅ ĐÚNG: Nested object có validation constraints
public record PatientInfo(
  @NotNull
  @Positive
  Long patientId,

  @NotBlank
  @Size(min = 2, max = 100)
  String fullName,

  @NotBlank
  @Pattern(regexp = "^(\\+84|0)[0-9]{9,10}$")
  String phoneNumber,

  @Email
  String email
) {}

public record DoctorInfo(
  @NotNull
  @Positive
  Long doctorId,

  @NotBlank
  String specialization
) {}

public record ServiceItem(
  @NotNull
  @Positive
  Long serviceId,

  @NotBlank
  String serviceName,

  @NotNull
  @Positive
  BigDecimal price,

  @NotNull
  @Min(1)
  @Max(100)
  Integer quantity
) {}

// ✅ ĐÚNG: Deep nesting với @Valid cascade
public record OrderRequest(
  @NotBlank
  String orderNumber,

  @NotNull
  @Valid
  ShippingInfo shipping,

  @NotEmpty
  @Valid
  List<OrderItem> items
) {}

public record ShippingInfo(
  @NotBlank
  String recipientName,

  @NotNull
  @Valid
  Address address, // Another nested level

  @Pattern(regexp = "^(\\+84|0)[0-9]{9,10}$")
  String phoneNumber
) {}

public record Address(
  @NotBlank
  @Size(max = 200)
  String street,

  @NotBlank
  @Size(max = 100)
  String city,

  @NotBlank
  @Pattern(regexp = "^[0-9]{5,6}$")
  String postalCode
) {}

public record OrderItem(
  @NotNull
  Long productId,

  @NotNull
  @Min(1)
  Integer quantity
) {}
```

### ❌ Cách sai

```java
// ❌ SAI: Thiếu @Valid trên nested object
public record CreateAppointmentRequest(
  @NotNull
  LocalDateTime appointmentTime,

  // ❌ Thiếu @Valid - nested object không được validate!
  @NotNull
  PatientInfo patient,

  @NotNull
  DoctorInfo doctor,

  // ❌ Thiếu @Valid - collection elements không được validate!
  @NotEmpty
  List<ServiceItem> services
) {}

// Kết quả: PatientInfo với phoneNumber = null vẫn pass validation!

// ❌ SAI: Manual validation trong service
@Service
public class AppointmentService {

  public void createAppointment(CreateAppointmentRequest request) {
    // Manual validation cho nested objects
    if (request.patient().fullName() == null) {
      throw new ValidationException("Patient name is required");
    }

    if (request.services().isEmpty()) {
      throw new ValidationException("At least one service required");
    }

    for (var service : request.services()) {
      if (service.quantity() < 1) {
        throw new ValidationException("Invalid quantity");
      }
    }

    // Rải rác, khó maintain, duplicate logic
  }
}

// ❌ SAI: Flatten structure thay vì nested (anti-pattern)
public record CreateAppointmentRequest(
  LocalDateTime appointmentTime,
  String reason,

  // Flatten thay vì nested - mất tính modular
  @NotNull Long patientId,
  @NotBlank String patientName,
  @NotBlank String patientPhone,

  @NotNull Long doctorId,
  @NotBlank String doctorSpecialization

  // Không thể validate collection như thế này
) {}
```

### Phát hiện

```regex
# Tìm nested objects thiếu @Valid
@NotNull\s+(?!@Valid)\s+\w+(Info|Request|Data|Details)

# Tìm List/Set thiếu @Valid
@NotEmpty\s+(?!@Valid)\s+List<

# Tìm manual nested validation trong service
for.*\w+\s+:\s+request\.\w+\(\).*\{[\s\S]*?if.*null
```

### Checklist

- [ ] `@Valid` trên tất cả nested object fields
- [ ] `@Valid` trên tất cả collection fields (`List`, `Set`, `Map`)
- [ ] Nested objects có validation constraints riêng
- [ ] Deep nesting (3+ levels) có `@Valid` cascade đầy đủ
- [ ] Không flatten structure để tránh nested validation
- [ ] Không có manual validation cho nested objects trong service
- [ ] Test cases verify nested validation hoạt động

---

## 12.05 Whitelist input fields (không bind tất cả)

### 🔴 BẮT BUỘC

### Metadata
- **ID:** `VP-12.05`
- **Severity:** CRITICAL
- **Phạm vi:** Data binding security
- **Công cụ:** DTO pattern, `@JsonProperty`, `@JsonIgnore`

### Tại sao?
- **Mass Assignment Attack:** Attacker gửi thêm fields không mong muốn (VD: `isAdmin=true`)
- **Data integrity:** Chỉ cho phép update fields được phép
- **Security-first:** Default deny, explicit allow
- **Audit trail:** Rõ ràng fields nào có thể bị thay đổi từ client

### ✅ Cách đúng

```java
// ✅ ĐÚNG: DTO chỉ chứa fields cho phép từ client (whitelist)
package jp.medicalbox.dto.user;

public record UpdateProfileRequest(
  // Chỉ 3 fields này được phép update từ client
  @NotBlank
  @Size(min = 2, max = 100)
  String fullName,

  @Pattern(regexp = "^(\\+84|0)[0-9]{9,10}$")
  String phoneNumber,

  @Past
  LocalDate birthDate
) {
  // ❌ KHÔNG có: isAdmin, role, createdAt, balance, etc.
  // Những fields này chỉ được update từ backend logic
}

// ✅ ĐÚNG: Entity có nhiều fields hơn DTO
@Entity
@Table(name = "users")
public class User {
  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Long id;

  private String email;
  private String fullName;
  private String phoneNumber;
  private LocalDate birthDate;

  // Fields KHÔNG được client update
  private Boolean isAdmin;        // ❌ Không expose trong DTO
  private String role;            // ❌ Không expose trong DTO
  private LocalDateTime createdAt; // ❌ Không expose trong DTO
  private BigDecimal balance;     // ❌ Không expose trong DTO
  private Boolean isActive;       // ❌ Không expose trong DTO

  // Getters/Setters
}

// ✅ ĐÚNG: Service chỉ update fields từ DTO
@Service
public class UserService {

  public UserResponse updateProfile(Long userId, UpdateProfileRequest request) {
    var user = userRepository.findById(userId)
      .orElseThrow(() -> new NotFoundException("User not found"));

    // Chỉ update fields có trong DTO (whitelist)
    user.setFullName(request.fullName());
    user.setPhoneNumber(request.phoneNumber());
    user.setBirthDate(request.birthDate());

    // ❌ KHÔNG update: isAdmin, role, balance, etc.
    // Các fields này chỉ được update qua admin API riêng

    return userMapper.toResponse(userRepository.save(user));
  }
}

// ✅ ĐÚNG: Admin API có DTO riêng với more fields
public record AdminUpdateUserRequest(
  @NotBlank String fullName,
  String phoneNumber,
  LocalDate birthDate,

  // Fields chỉ admin được update
  Boolean isAdmin,
  String role,
  Boolean isActive
) {}

// ✅ ĐÚNG: Sử dụng @JsonIgnore cho sensitive fields trong response
public record UserResponse(
  Long id,
  String email,
  String fullName,
  String phoneNumber,
  LocalDate birthDate,
  Boolean isActive,

  @JsonIgnore // Không expose ra JSON response
  String passwordHash,

  @JsonIgnore
  String resetToken
) {}

// ✅ ĐÚNG: Sử dụng @JsonProperty(access = READ_ONLY)
public class UserEntity {

  @JsonProperty(access = JsonProperty.Access.READ_ONLY)
  private Long id; // Chỉ serialize, không deserialize

  @JsonProperty(access = JsonProperty.Access.READ_ONLY)
  private LocalDateTime createdAt;

  @JsonProperty(access = JsonProperty.Access.WRITE_ONLY)
  private String password; // Chỉ deserialize, không serialize

  private String email; // Cả 2 chiều
}
```

### ❌ Cách sai

```java
// ❌ SAI: Dùng Entity làm DTO (bind toàn bộ fields)
@RestController
public class UserController {

  @PutMapping("/profile")
  public ResponseEntity<?> updateProfile(
    @RequestBody User user // ❌ Attacker có thể gửi isAdmin=true!
  ) {
    return ResponseEntity.ok(userRepository.save(user));
  }
}

// ❌ SAI: DTO chứa fields không nên cho client update
public record UpdateProfileRequest(
  String fullName,
  String phoneNumber,

  // ❌ NGUY HIỂM: Client có thể tự set admin
  Boolean isAdmin,

  // ❌ NGUY HIỂM: Client có thể tự thay đổi số dư
  BigDecimal balance,

  // ❌ NGUY HIỂM: Client có thể fake thời gian tạo
  LocalDateTime createdAt
) {}

// ❌ SAI: Dùng Map<String, Object> (blacklist approach)
@PutMapping("/profile")
public ResponseEntity<?> updateProfile(
  @RequestBody Map<String, Object> updates
) {
  var user = getCurrentUser();

  // ❌ Blacklist approach - dễ quên fields
  updates.remove("isAdmin");
  updates.remove("role");
  updates.remove("balance");

  // ❌ Vẫn có thể bị bypass nếu quên 1 field nào đó
  objectMapper.updateValue(user, updates);

  return ResponseEntity.ok(userRepository.save(user));
}

// ❌ SAI: Dùng BeanUtils.copyProperties với source chưa filter
@Service
public class UserService {

  public void updateProfile(Long id, Map<String, Object> updates) {
    var user = userRepository.findById(id).orElseThrow();

    // ❌ Copy tất cả properties - mass assignment vulnerability!
    BeanUtils.copyProperties(updates, user);

    userRepository.save(user);
  }
}
```

### Phát hiện

```regex
# Tìm Entity được dùng làm @RequestBody
@RequestBody\s+(?!.*Request|.*DTO|.*Command)\w+Entity

# Tìm Map<String, Object> trong @RequestBody
@RequestBody\s+Map<String,\s*Object>

# Tìm BeanUtils.copyProperties không safe
BeanUtils\.copyProperties\(

# Tìm DTO có fields nguy hiểm
(isAdmin|role|balance|createdAt|updatedAt|password)\s*;
```

### Checklist

- [ ] Không bao giờ dùng Entity làm `@RequestBody` DTO
- [ ] Request DTO chỉ chứa fields được phép từ client (whitelist)
- [ ] Sensitive fields (`isAdmin`, `role`, `balance`) không có trong request DTO
- [ ] System fields (`id`, `createdAt`, `updatedAt`) dùng `@JsonProperty(READ_ONLY)`
- [ ] Password fields dùng `@JsonProperty(WRITE_ONLY)`
- [ ] Không dùng `Map<String, Object>` cho data binding
- [ ] Không dùng `BeanUtils.copyProperties` với untrusted input
- [ ] Admin operations có DTO riêng với more privileged fields

---

## 12.06 Custom error messages (i18n ready)

### 🟡 NÊN CÓ

### Metadata
- **ID:** `VP-12.06`
- **Severity:** MEDIUM
- **Phạm vi:** Validation error messages
- **Công cụ:** `message` attribute, `MessageSource`

### Tại sao?
- **User experience:** Error messages rõ ràng, dễ hiểu
- **Internationalization:** Hỗ trợ đa ngôn ngữ
- **Consistency:** Format error messages nhất quán
- **Debugging:** Developer và user đều hiểu lỗi gì

### ✅ Cách đúng

```java
// ✅ ĐÚNG: Custom messages với i18n keys
package jp.medicalbox.dto.auth;

public record RegisterRequest(
  @NotBlank(message = "{validation.email.required}")
  @Email(message = "{validation.email.invalid}")
  @Size(max = 100, message = "{validation.email.maxLength}")
  String email,

  @NotBlank(message = "{validation.password.required}")
  @Size(
    min = 8,
    max = 100,
    message = "{validation.password.length}"
  )
  @Pattern(
    regexp = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d).*$",
    message = "{validation.password.complexity}"
  )
  String password,

  @NotBlank(message = "{validation.fullName.required}")
  @Size(
    min = 2,
    max = 100,
    message = "{validation.fullName.length}"
  )
  String fullName,

  @Past(message = "{validation.birthDate.past}")
  LocalDate birthDate
) {}

// ✅ ĐÚNG: Messages properties file - messages_vi.properties
validation.email.required=Email không được để trống
validation.email.invalid=Email không hợp lệ
validation.email.maxLength=Email tối đa {max} ký tự

validation.password.required=Mật khẩu không được để trống
validation.password.length=Mật khẩu phải từ {min} đến {max} ký tự
validation.password.complexity=Mật khẩu phải có chữ hoa, chữ thường và số

validation.fullName.required=Họ tên không được để trống
validation.fullName.length=Họ tên phải từ {min} đến {max} ký tự

validation.birthDate.past=Ngày sinh phải là ngày trong quá khứ

// ✅ ĐÚNG: Messages properties file - messages_en.properties
validation.email.required=Email is required
validation.email.invalid=Email is invalid
validation.email.maxLength=Email must be at most {max} characters

validation.password.required=Password is required
validation.password.length=Password must be between {min} and {max} characters
validation.password.complexity=Password must contain uppercase, lowercase and digit

validation.fullName.required=Full name is required
validation.fullName.length=Full name must be between {min} and {max} characters

validation.birthDate.past=Birth date must be in the past

// ✅ ĐÚNG: MessageSource configuration
@Configuration
public class MessageSourceConfig {

  @Bean
  public MessageSource messageSource() {
    var messageSource = new ReloadableResourceBundleMessageSource();
    messageSource.setBasename("classpath:messages");
    messageSource.setDefaultEncoding("UTF-8");
    messageSource.setCacheSeconds(3600);
    return messageSource;
  }

  @Bean
  public LocalValidatorFactoryBean validator(MessageSource messageSource) {
    var validator = new LocalValidatorFactoryBean();
    validator.setValidationMessageSource(messageSource);
    return validator;
  }
}

// ✅ ĐÚNG: Global exception handler với i18n
@RestControllerAdvice
public class GlobalExceptionHandler {

  private final MessageSource messageSource;

  @ExceptionHandler(MethodArgumentNotValidException.class)
  public ResponseEntity<ErrorResponse> handleValidation(
    MethodArgumentNotValidException ex,
    Locale locale
  ) {
    Map<String, String> errors = new HashMap<>();

    ex.getBindingResult().getFieldErrors().forEach(error -> {
      String message = messageSource.getMessage(
        error.getDefaultMessage(),
        error.getArguments(),
        locale
      );
      errors.put(error.getField(), message);
    });

    return ResponseEntity
      .status(HttpStatus.BAD_REQUEST)
      .body(new ErrorResponse("VALIDATION_FAILED", errors));
  }
}

// ✅ ĐÚNG: Custom validator với i18n message
@Constraint(validatedBy = UniqueEmailValidator.class)
public @interface UniqueEmail {

  String message() default "{validation.email.unique}";

  Class<?>[] groups() default {};

  Class<? extends Payload>[] payload() default {};
}

// messages_vi.properties
validation.email.unique=Email đã tồn tại trong hệ thống

// messages_en.properties
validation.email.unique=Email already exists in the system
```

### ❌ Cách sai

```java
// ❌ SAI: Hardcoded messages, không i18n
public record RegisterRequest(
  @NotBlank(message = "Email không được để trống") // ❌ Hardcoded tiếng Việt
  @Email(message = "Email is invalid")              // ❌ Hardcoded tiếng Anh
  String email,

  @Size(min = 8, message = "Password too short")   // ❌ Không consistent
  String password
) {}

// ❌ SAI: Default messages, không rõ ràng
public record RegisterRequest(
  @NotBlank // Message: "must not be blank" - không user-friendly
  @Email    // Message: "must be a well-formed email address" - quá dài
  String email,

  @Size(min = 8) // Message: "size must be between 8 and 2147483647"
  String password
) {}

// ❌ SAI: Exception messages không i18n
@Service
public class AuthService {

  public void register(RegisterRequest request) {
    if (userRepository.existsByEmail(request.email())) {
      // ❌ Hardcoded message
      throw new BusinessException("Email already exists");
    }
  }
}

// ❌ SAI: Trộn lẫn i18n keys và hardcoded messages
public record UserRequest(
  @NotBlank(message = "{validation.email.required}") // ✅ i18n key
  String email,

  @NotBlank(message = "Password is required")        // ❌ Hardcoded
  String password
) {}
```

### Phát hiện

```regex
# Tìm validation annotations thiếu message attribute
@(NotNull|NotBlank|NotEmpty|Email|Size|Pattern)\s*$

# Tìm hardcoded Vietnamese messages
message\s*=\s*"[^"]*[àáảãạăắằẳẵặâấầẩẫậèéẻẽẹêếềểễệìíỉĩịòóỏõọôốồổỗộơớờởỡợùúủũụưứừửữựỳýỷỹỵđ]

# Tìm hardcoded English messages (không phải i18n key)
message\s*=\s*"(?!\{)[A-Za-z\s]+(?!\})

# Tìm exception messages hardcoded
throw new \w+Exception\("[^{]
```

### Checklist

- [ ] Tất cả validation annotations có `message` attribute
- [ ] Messages dùng i18n keys (`{validation.xxx.yyy}`)
- [ ] File `messages_vi.properties` và `messages_en.properties` đầy đủ
- [ ] MessageSource configured với UTF-8 encoding
- [ ] LocalValidatorFactoryBean dùng custom MessageSource
- [ ] Global exception handler resolve messages theo Locale
- [ ] Custom validators dùng i18n keys
- [ ] Business exception messages cũng i18n (nếu user-facing)

---

## 12.07 @JsonIgnoreProperties(ignoreUnknown=true)

### 🟠 KHUYẾN NGHỊ

### Metadata
- **ID:** `VP-12.07`
- **Severity:** HIGH
- **Phạm vi:** JSON deserialization
- **Công cụ:** `@JsonIgnoreProperties`, Jackson

### Tại sao?
- **API evolution:** Frontend gửi thêm fields mới, backend cũ không crash
- **Backward compatibility:** Không break khi frontend deploy trước backend
- **Robustness:** Tránh deserialization errors do extra fields
- **Flexibility:** Cho phép gradual migration

### ✅ Cách đúng

```java
// ✅ ĐÚNG: ignoreUnknown=true trên request DTOs
package jp.medicalbox.dto.user;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

@JsonIgnoreProperties(ignoreUnknown = true)
public record UpdateProfileRequest(
  @NotBlank
  String fullName,

  String phoneNumber,

  LocalDate birthDate
) {}
// Frontend có thể gửi thêm fields (VD: avatar, bio)
// mà backend không crash

// ✅ ĐÚNG: Global ObjectMapper configuration
@Configuration
public class JacksonConfig {

  @Bean
  public ObjectMapper objectMapper() {
    var mapper = new ObjectMapper();

    // Ignore unknown properties globally
    mapper.configure(
      DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES,
      false
    );

    // Other configurations
    mapper.registerModule(new JavaTimeModule());
    mapper.disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);

    return mapper;
  }
}

// ✅ ĐÚNG: Kết hợp với @JsonProperty cho renamed fields
@JsonIgnoreProperties(ignoreUnknown = true)
public record UserResponse(
  Long id,

  @JsonProperty("full_name") // API dùng snake_case
  String fullName,

  @JsonProperty("phone_number")
  String phoneNumber,

  @JsonProperty("birth_date")
  LocalDate birthDate
) {}

// ✅ ĐÚNG: ignoreUnknown cho external API integration
@JsonIgnoreProperties(ignoreUnknown = true)
public record ExternalPaymentResponse(
  String transactionId,
  String status,
  BigDecimal amount

  // External API có thể trả về thêm 20+ fields khác
  // Ta chỉ quan tâm 3 fields này
) {}

// ✅ ĐÚNG: Kết hợp với @JsonInclude cho response DTOs
@JsonIgnoreProperties(ignoreUnknown = true)
@JsonInclude(JsonInclude.Include.NON_NULL)
public record ApiResponse<T>(
  Boolean success,
  T data,
  String error,

  @JsonProperty("error_code")
  String errorCode
) {}
```

### ❌ Cách sai

```java
// ❌ SAI: Không có ignoreUnknown - fail khi có extra fields
public record UpdateProfileRequest(
  String fullName,
  String phoneNumber
) {}
// Frontend gửi { fullName, phoneNumber, avatar }
// => UnrecognizedPropertyException!

// ❌ SAI: Dùng ignoreUnknown=false explicitly
@JsonIgnoreProperties(ignoreUnknown = false) // ❌ Strict mode
public record UserRequest(
  String email,
  String password
) {}
// API không flexible, dễ break

// ❌ SAI: Không config ObjectMapper globally
// => Mỗi DTO phải thêm @JsonIgnoreProperties manually
public record Request1(String field1) {}
public record Request2(String field2) {}
public record Request3(String field3) {}
// Thiếu 1 DTO => potential crash

// ❌ SAI: Dùng Map<String, Object> để tránh unknown fields
@PostMapping("/update")
public ResponseEntity<?> update(
  @RequestBody Map<String, Object> request
) {
  // ❌ Mất type safety, validation không hoạt động
  String fullName = (String) request.get("fullName");
  // Có thể ClassCastException!
}
```

### Phát hiện

```regex
# Tìm DTOs thiếu @JsonIgnoreProperties
public record \w+Request\((?!.*@JsonIgnoreProperties)

# Tìm ignoreUnknown=false (anti-pattern)
@JsonIgnoreProperties\(ignoreUnknown\s*=\s*false

# Tìm Map<String, Object> trong @RequestBody
@RequestBody\s+Map<String,\s*Object>
```

### Checklist

- [ ] `@JsonIgnoreProperties(ignoreUnknown = true)` trên request DTOs
- [ ] Global ObjectMapper configured với `FAIL_ON_UNKNOWN_PROPERTIES = false`
- [ ] Response DTOs cũng có `ignoreUnknown = true` (cho external APIs)
- [ ] Kết hợp với `@JsonInclude(NON_NULL)` khi cần
- [ ] Không dùng `Map<String, Object>` để bypass unknown fields
- [ ] Test cases verify extra fields không gây crash

---

## 12.08 Date/Time format chuẩn ISO-8601

### 🟠 KHUYẾN NGHỊ

### Metadata
- **ID:** `VP-12.08`
- **Severity:** HIGH
- **Phạm vi:** Date/Time serialization
- **Công cụ:** `JavaTimeModule`, `@JsonFormat`

### Tại sao?
- **Standard:** ISO-8601 là chuẩn quốc tế (2024-01-15T14:30:00Z)
- **Timezone safe:** Rõ ràng về timezone, tránh ambiguity
- **Interoperability:** Frontend (JavaScript Date), mobile, external APIs đều hiểu
- **No timestamp integers:** Tránh dùng Unix timestamp (khó đọc, dễ nhầm milliseconds/seconds)

### ✅ Cách đúng

```java
// ✅ ĐÚNG: Sử dụng java.time.* classes (Java 8+)
package jp.medicalbox.dto.appointment;

import java.time.*;

public record AppointmentResponse(
  Long id,

  // LocalDateTime cho datetime không timezone (2024-01-15T14:30:00)
  LocalDateTime appointmentTime,

  // ZonedDateTime cho datetime có timezone (2024-01-15T14:30:00+09:00)
  ZonedDateTime createdAt,

  // LocalDate cho date only (2024-01-15)
  LocalDate appointmentDate,

  // LocalTime cho time only (14:30:00)
  LocalTime appointmentTimeSlot,

  // Instant cho UTC timestamp (2024-01-15T05:30:00Z)
  Instant lastUpdated
) {}

// ✅ ĐÚNG: Global Jackson configuration
@Configuration
public class JacksonConfig {

  @Bean
  public ObjectMapper objectMapper() {
    var mapper = new ObjectMapper();

    // Enable JavaTimeModule để serialize ISO-8601
    mapper.registerModule(new JavaTimeModule());

    // Không dùng timestamps (integers)
    mapper.disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);

    return mapper;
  }
}

// ✅ ĐÚNG: Custom format nếu cần (rare cases)
public record CustomDateResponse(
  @JsonFormat(pattern = "yyyy-MM-dd HH:mm:ss", timezone = "Asia/Tokyo")
  LocalDateTime appointmentTime,

  @JsonFormat(pattern = "yyyy-MM-dd")
  LocalDate birthDate
) {}

// ✅ ĐÚNG: Request DTO với validation
public record CreateAppointmentRequest(
  @NotNull
  @FutureOrPresent(message = "{validation.appointmentTime.future}")
  LocalDateTime appointmentTime, // Accept: "2024-01-15T14:30:00"

  @NotNull
  @Future
  LocalDate appointmentDate // Accept: "2024-01-15"
) {}

// ✅ ĐÚNG: Timezone handling cho multi-region app
@Service
public class AppointmentService {

  public void createAppointment(CreateAppointmentRequest request) {
    // Convert client LocalDateTime to server ZonedDateTime
    var clientZone = ZoneId.of("Asia/Tokyo");
    var serverZone = ZoneId.systemDefault();

    var appointmentTime = request.appointmentTime()
      .atZone(clientZone)
      .withZoneSameInstant(serverZone);

    // Store as ZonedDateTime or Instant
    var appointment = new Appointment();
    appointment.setAppointmentTime(appointmentTime);
    appointmentRepository.save(appointment);
  }
}

// ✅ ĐÚNG: Database column với timezone
@Entity
@Table(name = "appointments")
public class Appointment {

  @Column(name = "appointment_time", columnDefinition = "TIMESTAMP WITH TIME ZONE")
  private ZonedDateTime appointmentTime;

  @Column(name = "created_at", columnDefinition = "TIMESTAMP WITH TIME ZONE")
  private Instant createdAt;

  @Column(name = "appointment_date")
  private LocalDate appointmentDate;
}
```

### ❌ Cách sai

```java
// ❌ SAI: Dùng java.util.Date (deprecated)
public record AppointmentResponse(
  Long id,
  Date appointmentTime, // ❌ Legacy class, không timezone safe
  Date createdAt
) {}

// ❌ SAI: Dùng String cho date/time
public record CreateAppointmentRequest(
  String appointmentTime, // ❌ "2024-01-15 14:30:00" - ambiguous format
  String appointmentDate  // ❌ Không validation, dễ parse error
) {}

// ❌ SAI: Dùng Unix timestamp (Long)
public record AppointmentResponse(
  Long id,
  Long appointmentTime, // ❌ 1705302600000 - khó đọc, dễ nhầm unit
  Long createdAt        // ❌ Milliseconds hay seconds?
) {}

// ❌ SAI: Custom date format không chuẩn
@JsonFormat(pattern = "dd/MM/yyyy HH:mm") // ❌ Không ISO-8601
private LocalDateTime appointmentTime;

@JsonFormat(pattern = "MM-dd-yyyy") // ❌ American format, confusing
private LocalDate birthDate;

// ❌ SAI: Không disable WRITE_DATES_AS_TIMESTAMPS
@Configuration
public class JacksonConfig {

  @Bean
  public ObjectMapper objectMapper() {
    var mapper = new ObjectMapper();
    mapper.registerModule(new JavaTimeModule());
    // ❌ Thiếu disable timestamps
    // => LocalDateTime serialize thành [2024,1,15,14,30,0]
    return mapper;
  }
}

// ❌ SAI: Không xử lý timezone
@Service
public class AppointmentService {

  public void createAppointment(CreateAppointmentRequest request) {
    var appointment = new Appointment();

    // ❌ LocalDateTime không có timezone info
    // Server ở timezone khác client => sai giờ!
    appointment.setAppointmentTime(request.appointmentTime());

    appointmentRepository.save(appointment);
  }
}
```

### Phát hiện

```regex
# Tìm java.util.Date usage
import java\.util\.Date;
private Date \w+;

# Tìm String cho date/time fields
(appointmentTime|createdAt|updatedAt|birthDate|startDate|endDate)\s+String

# Tìm Long/Integer cho timestamps
(Time|Date|At)\s+(Long|Integer)

# Tìm custom date formats không ISO-8601
@JsonFormat\(pattern\s*=\s*"(?!yyyy-MM-dd)
```

### Checklist

- [ ] Dùng `java.time.*` classes (`LocalDateTime`, `ZonedDateTime`, `Instant`, `LocalDate`)
- [ ] Không dùng `java.util.Date`, `java.sql.Date`, `Calendar`
- [ ] Không dùng `String` hoặc `Long` cho date/time
- [ ] JavaTimeModule registered trong ObjectMapper
- [ ] `WRITE_DATES_AS_TIMESTAMPS` disabled
- [ ] Default format là ISO-8601 (2024-01-15T14:30:00)
- [ ] Timezone handling rõ ràng cho multi-region apps
- [ ] Database columns dùng `TIMESTAMP WITH TIME ZONE` khi cần

---

## 12.09 Enum validation cho giá trị giới hạn

### 🟠 KHUYẾN NGHỊ

### Metadata
- **ID:** `VP-12.09`
- **Severity:** HIGH
- **Phạm vi:** Enum validation
- **Công cụ:** Java enum, `@JsonValue`, custom validator

### Tại sao?
- **Type safety:** Compile-time check thay vì runtime validation
- **Giới hạn values:** Chỉ cho phép giá trị trong enum
- **Tự động documentation:** Enum values rõ ràng trong code
- **Refactoring safe:** IDE tự động update khi đổi enum

### ✅ Cách đúng

```java
// ✅ ĐÚNG: Define enum cho giá trị giới hạn
package jp.medicalbox.enums;

import com.fasterxml.jackson.annotation.JsonValue;

public enum AppointmentStatus {
  PENDING("pending"),
  CONFIRMED("confirmed"),
  IN_PROGRESS("in_progress"),
  COMPLETED("completed"),
  CANCELLED("cancelled"),
  NO_SHOW("no_show");

  private final String value;

  AppointmentStatus(String value) {
    this.value = value;
  }

  @JsonValue // Serialize thành "pending" thay vì "PENDING"
  public String getValue() {
    return value;
  }

  @JsonCreator // Deserialize từ "pending" thành PENDING
  public static AppointmentStatus fromValue(String value) {
    for (var status : values()) {
      if (status.value.equals(value)) {
        return status;
      }
    }
    throw new IllegalArgumentException("Invalid status: " + value);
  }
}

// ✅ ĐÚNG: Sử dụng enum trong DTO
public record UpdateAppointmentRequest(
  @NotNull(message = "{validation.status.required}")
  AppointmentStatus status, // Type-safe, chỉ nhận giá trị hợp lệ

  String notes
) {}

// JSON: { "status": "confirmed", "notes": "..." }
// "invalid_status" => IllegalArgumentException tự động

// ✅ ĐÚNG: Enum trong Entity
@Entity
@Table(name = "appointments")
public class Appointment {

  @Enumerated(EnumType.STRING) // Store "PENDING" trong DB
  @Column(name = "status", nullable = false)
  private AppointmentStatus status;

  // Hoặc dùng converter cho custom values
  @Convert(converter = AppointmentStatusConverter.class)
  @Column(name = "status")
  private AppointmentStatus status;
}

// ✅ ĐÚNG: JPA Converter cho enum
@Converter(autoApply = true)
public class AppointmentStatusConverter
  implements AttributeConverter<AppointmentStatus, String> {

  @Override
  public String convertToDatabaseColumn(AppointmentStatus status) {
    return status == null ? null : status.getValue();
  }

  @Override
  public AppointmentStatus convertToEntityAttribute(String value) {
    return value == null ? null : AppointmentStatus.fromValue(value);
  }
}

// ✅ ĐÚNG: Enum với business logic
public enum UserRole {
  USER(1),
  CLINIC(3),
  OPERATOR(2),
  ADMIN(99);

  private final int level;

  UserRole(int level) {
    this.level = level;
  }

  public boolean canAccess(UserRole requiredRole) {
    return this.level >= requiredRole.level;
  }

  public boolean isAdmin() {
    return this == ADMIN;
  }
}

// ✅ ĐÚNG: Custom validator cho enum (nếu cần logic phức tạp)
@Documented
@Constraint(validatedBy = ValidStatusValidator.class)
@Target({ElementType.FIELD, ElementType.PARAMETER})
@Retention(RetentionPolicy.RUNTIME)
public @interface ValidStatus {

  String message() default "Invalid status";

  Class<?>[] groups() default {};

  Class<? extends Payload>[] payload() default {};

  AppointmentStatus[] allowed();
}

public class ValidStatusValidator
  implements ConstraintValidator<ValidStatus, AppointmentStatus> {

  private Set<AppointmentStatus> allowedStatuses;

  @Override
  public void initialize(ValidStatus annotation) {
    this.allowedStatuses = Set.of(annotation.allowed());
  }

  @Override
  public boolean isValid(AppointmentStatus status, ConstraintValidatorContext ctx) {
    return status == null || allowedStatuses.contains(status);
  }
}

// Sử dụng:
public record UpdateAppointmentRequest(
  @NotNull
  @ValidStatus(
    allowed = {AppointmentStatus.CONFIRMED, AppointmentStatus.CANCELLED},
    message = "Chỉ cho phép confirm hoặc cancel"
  )
  AppointmentStatus status
) {}
```

### ❌ Cách sai

```java
// ❌ SAI: Dùng String thay vì enum
public record UpdateAppointmentRequest(
  @NotBlank
  @Pattern(regexp = "pending|confirmed|completed|cancelled") // ❌ Dễ typo
  String status
) {}

// ❌ SAI: Dùng constants thay vì enum
public class AppointmentStatus {
  public static final String PENDING = "pending";
  public static final String CONFIRMED = "confirmed";
  public static final String COMPLETED = "completed";
  // ❌ Không type-safe, có thể truyền random string
}

public record UpdateRequest(
  String status // ❌ Accept bất kỳ string nào
) {}

// ❌ SAI: Manual validation trong service
@Service
public class AppointmentService {

  private static final Set<String> VALID_STATUSES = Set.of(
    "pending", "confirmed", "completed", "cancelled"
  );

  public void updateStatus(Long id, String status) {
    if (!VALID_STATUSES.contains(status)) {
      throw new ValidationException("Invalid status");
    }
    // ❌ Validation logic rải rác, không tái sử dụng
  }
}

// ❌ SAI: Enum không có @JsonValue/@JsonCreator
public enum AppointmentStatus {
  PENDING,
  CONFIRMED,
  COMPLETED;
  // ❌ JSON serialize thành "PENDING" (uppercase)
  // Frontend expect "pending" (lowercase) => mismatch
}

// ❌ SAI: Dùng Integer cho enum
public record UpdateRequest(
  @Min(1) @Max(4)
  Integer status // ❌ Magic numbers, không rõ nghĩa
) {}

// 1 = PENDING? 2 = CONFIRMED? Ai biết được!
```

### Phát hiện

```regex
# Tìm String fields có pattern validation cho enum
@Pattern\(regexp\s*=\s*"[^"]+\|[^"]+"\)\s+String\s+(status|type|role)

# Tìm constants classes (anti-pattern)
public static final String (STATUS|TYPE|ROLE)_\w+

# Tìm Integer cho status/type/role
(status|type|role)\s+Integer

# Tìm manual enum validation
if\s*\(.*contains\((status|type|role)\)
```

### Checklist

- [ ] Giá trị giới hạn (status, type, role) dùng enum thay vì String
- [ ] Enum có `@JsonValue` cho serialize
- [ ] Enum có `@JsonCreator` static method cho deserialize
- [ ] Entity dùng `@Enumerated(EnumType.STRING)` hoặc custom converter
- [ ] Không dùng String constants class
- [ ] Không dùng Integer cho enum
- [ ] Không manual validation trong service
- [ ] Custom validator nếu cần giới hạn subset của enum values

---

## 12.10 Max size validation cho String/Collection inputs

### 🔴 BẮT BUỘC

### Metadata
- **ID:** `VP-12.10`
- **Severity:** CRITICAL
- **Phạm vi:** DoS prevention, data integrity
- **Công cụ:** `@Size`, `@Max`, custom limits

### Tại sao?
- **DoS prevention:** Attacker gửi 100MB string => OOM crash
- **Database constraints:** String quá dài => SQL error
- **Performance:** Large collections gây slow processing
- **Business rules:** Giới hạn hợp lý (email max 100 chars, description max 5000)

### ✅ Cách đúng

```java
// ✅ ĐÚNG: Max size cho tất cả String inputs
package jp.medicalbox.dto.user;

public record UpdateProfileRequest(
  @NotBlank
  @Size(min = 2, max = 100, message = "Họ tên từ 2-100 ký tự")
  String fullName,

  @Email
  @Size(max = 100, message = "Email tối đa 100 ký tự")
  String email,

  @Pattern(regexp = "^(\\+84|0)[0-9]{9,10}$")
  @Size(max = 15, message = "Số điện thoại tối đa 15 ký tự")
  String phoneNumber,

  @Size(max = 5000, message = "Mô tả tối đa 5000 ký tự")
  String bio,

  @Size(max = 500, message = "Địa chỉ tối đa 500 ký tự")
  String address
) {}

// ✅ ĐÚNG: Max size cho Collections
public record CreateAppointmentRequest(
  LocalDateTime appointmentTime,
  String reason,

  @NotEmpty(message = "Ít nhất 1 dịch vụ")
  @Size(max = 20, message = "Tối đa 20 dịch vụ")
  @Valid
  List<ServiceItem> services,

  @Size(max = 10, message = "Tối đa 10 file đính kèm")
  List<String> attachmentUrls,

  @Size(max = 100, message = "Tối đa 100 tag")
  Set<String> tags
) {}

// ✅ ĐÚNG: Global max size config
@Configuration
public class ValidationConfig {

  @Bean
  public Validator validator() {
    var config = Validation
      .byDefaultProvider()
      .configure()
      .addProperty("hibernate.validator.fail_fast", "false");

    return config.buildValidatorFactory().getValidator();
  }
}

// ✅ ĐÚNG: Controller-level size limits
@RestController
@RequestMapping("/api/appointments")
public class AppointmentController {

  // Limit request body size (Spring Boot)
  @PostMapping
  public ResponseEntity<AppointmentResponse> create(
    @Valid @RequestBody(required = true) CreateAppointmentRequest request
  ) {
    return ResponseEntity.ok(appointmentService.create(request));
  }
}

// application.yml
spring:
  servlet:
    multipart:
      max-file-size: 10MB       # File upload tối đa 10MB
      max-request-size: 50MB    # Toàn bộ request tối đa 50MB

server:
  max-http-header-size: 16KB    # Header tối đa 16KB

// ✅ ĐÚNG: Custom size constraints
package jp.medicalbox.validation;

@Documented
@Constraint(validatedBy = MaxFileSizeValidator.class)
@Target({ElementType.FIELD})
@Retention(RetentionPolicy.RUNTIME)
public @interface MaxFileSize {

  String message() default "File quá lớn";

  Class<?>[] groups() default {};

  Class<? extends Payload>[] payload() default {};

  long maxBytes(); // VD: 10 * 1024 * 1024 = 10MB
}

public class MaxFileSizeValidator
  implements ConstraintValidator<MaxFileSize, MultipartFile> {

  private long maxBytes;

  @Override
  public void initialize(MaxFileSize annotation) {
    this.maxBytes = annotation.maxBytes();
  }

  @Override
  public boolean isValid(MultipartFile file, ConstraintValidatorContext context) {
    if (file == null || file.isEmpty()) {
      return true;
    }
    return file.getSize() <= maxBytes;
  }
}

// ✅ ĐÚNG: Database constraints match validation
@Entity
@Table(name = "users")
public class User {

  @Column(name = "full_name", length = 100, nullable = false)
  private String fullName; // Match @Size(max = 100)

  @Column(name = "email", length = 100, nullable = false, unique = true)
  private String email; // Match @Size(max = 100)

  @Column(name = "bio", length = 5000)
  private String bio; // Match @Size(max = 5000)
}

// ✅ ĐÚNG: Request timeout protection
@Configuration
public class WebMvcConfig implements WebMvcConfigurer {

  @Override
  public void configureAsyncSupport(AsyncSupportConfigurer configurer) {
    configurer.setDefaultTimeout(30_000); // 30 seconds
    configurer.setTaskExecutor(taskExecutor());
  }
}
```

### ❌ Cách sai

```java
// ❌ SAI: Không có max size validation
public record UpdateProfileRequest(
  String fullName,    // ❌ Attacker gửi 10MB string!
  String email,       // ❌ Không limit
  String bio,         // ❌ Có thể 100MB
  List<String> tags   // ❌ Có thể 1 triệu items
) {}

// ❌ SAI: Max size quá lớn (unrealistic)
public record UserRequest(
  @Size(max = 1_000_000) // ❌ 1 triệu ký tự cho full name?
  String fullName,

  @Size(max = Integer.MAX_VALUE) // ❌ Vô nghĩa
  String description
) {}

// ❌ SAI: Database constraints không match validation
public record UpdateProfileRequest(
  @Size(max = 200)
  String fullName
) {}

@Entity
public class User {
  @Column(length = 100) // ❌ Mismatch: DTO max=200, DB max=100
  private String fullName;
  // => SQL error khi insert
}

// ❌ SAI: Không limit collection size
public record BulkCreateRequest(
  List<CreateUserRequest> users // ❌ Attacker gửi 1 triệu users
) {}

@PostMapping("/bulk-create")
public void bulkCreate(@Valid @RequestBody BulkCreateRequest request) {
  request.users().forEach(userService::create); // ❌ DoS!
}

// ❌ SAI: Không config global request size limits
// application.yml
spring:
  servlet:
    multipart:
      max-file-size: -1    # ❌ Unlimited!
      max-request-size: -1 # ❌ Unlimited!
```

### Phát hiện

```regex
# Tìm String fields thiếu @Size
(?<!@Size).*String\s+\w+;

# Tìm List/Set/Map thiếu @Size
(?<!@Size).*List<.*>\s+\w+;
(?<!@Size).*Set<.*>\s+\w+;

# Tìm @Size với max quá lớn
@Size\(max\s*=\s*(100000|Integer\.MAX_VALUE)

# Tìm MultipartFile thiếu size validation
MultipartFile\s+\w+(?!.*@MaxFileSize)
```

### Checklist

- [ ] Tất cả String fields có `@Size(max = X)`
- [ ] Max size hợp lý theo business rules (fullName=100, bio=5000, etc.)
- [ ] Tất cả Collection fields có `@Size(max = X)`
- [ ] Database column `length` match với `@Size(max)`
- [ ] Global request size limits configured (`max-request-size`)
- [ ] File upload size limits configured (`max-file-size`)
- [ ] Request timeout configured (prevent slow DoS)
- [ ] No unrealistic max sizes (1M chars, Integer.MAX_VALUE)

---

## Tổng kết Domain 12

### Checklist tổng hợp

**Bean Validation (12.01)**
- [ ] Tất cả DTO có Bean Validation annotations
- [ ] `@Valid` trên `@RequestBody` parameters
- [ ] Global exception handler cho validation errors

**Custom Validators (12.02)**
- [ ] Business rules phức tạp dùng custom `@Constraint`
- [ ] Cross-field validation dùng class-level annotation
- [ ] Custom validators có unit tests

**Validation Groups (12.03)**
- [ ] Dùng `@Validated(Group.class)` thay vì `@Valid`
- [ ] Define `ValidationGroups` interface
- [ ] Không duplicate DTOs cho create/update

**Nested Validation (12.04)**
- [ ] `@Valid` trên nested objects và collections
- [ ] Deep nesting có cascade validation đầy đủ

**Whitelist Binding (12.05)**
- [ ] Không dùng Entity làm `@RequestBody`
- [ ] Request DTO chỉ chứa allowed fields
- [ ] Sensitive fields không expose

**I18n Messages (12.06)**
- [ ] Validation messages dùng i18n keys
- [ ] File `messages_vi.properties` và `messages_en.properties`
- [ ] MessageSource configured

**Ignore Unknown (12.07)**
- [ ] `@JsonIgnoreProperties(ignoreUnknown = true)` trên DTOs
- [ ] Global ObjectMapper configured

**ISO-8601 Dates (12.08)**
- [ ] Dùng `java.time.*` classes
- [ ] JavaTimeModule registered
- [ ] `WRITE_DATES_AS_TIMESTAMPS` disabled

**Enum Validation (12.09)**
- [ ] Giá trị giới hạn dùng enum thay vì String
- [ ] Enum có `@JsonValue` và `@JsonCreator`

**Max Size (12.10)**
- [ ] Tất cả String/Collection có `@Size(max)`
- [ ] Database constraints match validation
- [ ] Global request size limits configured

### Severity breakdown
- 🔴 **CRITICAL (3):** 12.01, 12.05, 12.10 - Bắt buộc cho mọi project
- 🟠 **HIGH (5):** 12.02, 12.04, 12.07, 12.08, 12.09 - Khuyến nghị mạnh
- 🟡 **MEDIUM (2):** 12.03, 12.06 - Nên có cho production app

### Anti-patterns cần tránh
1. Dùng Entity làm DTO
2. Manual validation trong service layer
3. Hardcoded validation messages
4. String thay vì enum cho giá trị giới hạn
5. Không giới hạn size cho inputs
6. java.util.Date thay vì java.time.*
7. Thiếu `@Valid` trên nested objects
8. ignoreUnknown = false (strict mode)

### Tools & Dependencies
```xml
<!-- pom.xml -->
<dependency>
  <groupId>org.springframework.boot</groupId>
  <artifactId>spring-boot-starter-validation</artifactId>
</dependency>

<dependency>
  <groupId>com.fasterxml.jackson.datatype</groupId>
  <artifactId>jackson-datatype-jsr310</artifactId>
</dependency>
```
