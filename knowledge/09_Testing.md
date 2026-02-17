# Domain 09: Testing
> **Số practices:** 10 | 🔴 4 | 🟠 3 | 🟡 3
> **Trọng số:** ×2 (QUAN TRỌNG)

---

## 09.01: Unit test cho Service layer (JUnit 5 + Mockito) 🔴

### Metadata
- **Mức độ:** 🔴 BẮT BUỘC
- **Lý do:** Đảm bảo business logic đúng, phát hiện bug sớm, dễ refactor
- **Công cụ:** JUnit 5, Mockito, AssertJ
- **Phạm vi:** Tất cả service classes có business logic

### Tại sao?
1. **Tách biệt logic**: Test business logic độc lập, không phụ thuộc DB/network
2. **Phát hiện bug sớm**: Catch lỗi logic trước khi integration test
3. **Tài liệu sống**: Test case là specification của behavior
4. **Refactor an toàn**: Đảm bảo logic không thay đổi sau khi refactor
5. **Fast feedback**: Unit test chạy nhanh (< 100ms/test)

### ✅ Cách đúng

```java
// Service cần test
@Service
@RequiredArgsConstructor
public class DoctorService {
  private final DoctorRepository doctorRepository;
  private final ActorService actorService;
  private final NotificationService notificationService;

  public DoctorDto createDoctor(CreateDoctorRequest request) {
    // Validate
    if (doctorRepository.existsByEmail(request.email())) {
      throw new DuplicateEmailException("Email đã tồn tại: " + request.email());
    }

    // Create actor
    RelActor actor = actorService.createActor(ActorType.CLINIC, request.actorRefId());

    // Create doctor
    MstDoctor doctor = MstDoctor.builder()
        .name(request.name())
        .email(request.email())
        .actor(actor)
        .status(DoctorStatus.ACTIVE)
        .build();

    MstDoctor saved = doctorRepository.save(doctor);

    // Send notification
    notificationService.sendWelcomeEmail(saved.getEmail());

    return DoctorMapper.toDto(saved);
  }

  public void updateDoctorStatus(Long doctorId, DoctorStatus newStatus) {
    MstDoctor doctor = doctorRepository.findById(doctorId)
        .orElseThrow(() -> new EntityNotFoundException("Doctor not found: " + doctorId));

    DoctorStatus oldStatus = doctor.getStatus();
    doctor.setStatus(newStatus);
    doctorRepository.save(doctor);

    // Send notification if status changed from ACTIVE to INACTIVE
    if (oldStatus == DoctorStatus.ACTIVE && newStatus == DoctorStatus.INACTIVE) {
      notificationService.sendDeactivationEmail(doctor.getEmail());
    }
  }
}

// ✅ Unit test đầy đủ
@ExtendWith(MockitoExtension.class)
class DoctorServiceTest {

  @Mock
  private DoctorRepository doctorRepository;

  @Mock
  private ActorService actorService;

  @Mock
  private NotificationService notificationService;

  @InjectMocks
  private DoctorService doctorService;

  @Nested
  @DisplayName("createDoctor()")
  class CreateDoctorTests {

    @Test
    void should_createDoctor_when_validRequest() {
      // Given
      CreateDoctorRequest request = new CreateDoctorRequest(
          "Dr. Nguyen Van A",
          "doctor.a@clinic.com",
          1001L
      );

      RelActor mockActor = RelActor.builder()
          .id(1L)
          .actorType(ActorType.CLINIC)
          .actorRefId(1001L)
          .build();

      MstDoctor expectedDoctor = MstDoctor.builder()
          .id(1L)
          .name("Dr. Nguyen Van A")
          .email("doctor.a@clinic.com")
          .actor(mockActor)
          .status(DoctorStatus.ACTIVE)
          .build();

      when(doctorRepository.existsByEmail(request.email())).thenReturn(false);
      when(actorService.createActor(ActorType.CLINIC, request.actorRefId())).thenReturn(mockActor);
      when(doctorRepository.save(any(MstDoctor.class))).thenReturn(expectedDoctor);

      // When
      DoctorDto result = doctorService.createDoctor(request);

      // Then
      assertThat(result).isNotNull();
      assertThat(result.name()).isEqualTo("Dr. Nguyen Van A");
      assertThat(result.email()).isEqualTo("doctor.a@clinic.com");
      assertThat(result.status()).isEqualTo(DoctorStatus.ACTIVE);

      // Verify interactions
      verify(doctorRepository).existsByEmail(request.email());
      verify(actorService).createActor(ActorType.CLINIC, 1001L);
      verify(doctorRepository).save(any(MstDoctor.class));
      verify(notificationService).sendWelcomeEmail("doctor.a@clinic.com");
    }

    @Test
    void should_throwException_when_emailAlreadyExists() {
      // Given
      CreateDoctorRequest request = new CreateDoctorRequest(
          "Dr. Nguyen Van A",
          "duplicate@clinic.com",
          1001L
      );

      when(doctorRepository.existsByEmail(request.email())).thenReturn(true);

      // When & Then
      assertThatThrownBy(() -> doctorService.createDoctor(request))
          .isInstanceOf(DuplicateEmailException.class)
          .hasMessageContaining("Email đã tồn tại: duplicate@clinic.com");

      // Verify không gọi save
      verify(doctorRepository, never()).save(any());
      verify(notificationService, never()).sendWelcomeEmail(any());
    }
  }

  @Nested
  @DisplayName("updateDoctorStatus()")
  class UpdateDoctorStatusTests {

    @Test
    void should_updateStatus_when_validRequest() {
      // Given
      Long doctorId = 1L;
      MstDoctor doctor = MstDoctor.builder()
          .id(doctorId)
          .status(DoctorStatus.ACTIVE)
          .email("doctor@clinic.com")
          .build();

      when(doctorRepository.findById(doctorId)).thenReturn(Optional.of(doctor));

      // When
      doctorService.updateDoctorStatus(doctorId, DoctorStatus.INACTIVE);

      // Then
      assertThat(doctor.getStatus()).isEqualTo(DoctorStatus.INACTIVE);
      verify(doctorRepository).save(doctor);
    }

    @Test
    void should_sendNotification_when_statusChangedFromActiveToInactive() {
      // Given
      Long doctorId = 1L;
      MstDoctor doctor = MstDoctor.builder()
          .id(doctorId)
          .status(DoctorStatus.ACTIVE)
          .email("doctor@clinic.com")
          .build();

      when(doctorRepository.findById(doctorId)).thenReturn(Optional.of(doctor));

      // When
      doctorService.updateDoctorStatus(doctorId, DoctorStatus.INACTIVE);

      // Then
      verify(notificationService).sendDeactivationEmail("doctor@clinic.com");
    }

    @Test
    void should_notSendNotification_when_statusNotChangedToInactive() {
      // Given
      Long doctorId = 1L;
      MstDoctor doctor = MstDoctor.builder()
          .id(doctorId)
          .status(DoctorStatus.ACTIVE)
          .email("doctor@clinic.com")
          .build();

      when(doctorRepository.findById(doctorId)).thenReturn(Optional.of(doctor));

      // When
      doctorService.updateDoctorStatus(doctorId, DoctorStatus.ACTIVE); // Không đổi

      // Then
      verify(notificationService, never()).sendDeactivationEmail(any());
    }

    @Test
    void should_throwException_when_doctorNotFound() {
      // Given
      Long doctorId = 999L;
      when(doctorRepository.findById(doctorId)).thenReturn(Optional.empty());

      // When & Then
      assertThatThrownBy(() -> doctorService.updateDoctorStatus(doctorId, DoctorStatus.INACTIVE))
          .isInstanceOf(EntityNotFoundException.class)
          .hasMessageContaining("Doctor not found: 999");

      verify(doctorRepository, never()).save(any());
    }
  }
}
```

### ❌ Cách sai

```java
// ❌ SAI: Không test edge cases
@Test
void testCreateDoctor() {
  // Chỉ test happy path, không test:
  // - Email trùng
  // - Input null
  // - ActorService throws exception
  CreateDoctorRequest request = new CreateDoctorRequest("Dr. A", "a@clinic.com", 1L);
  DoctorDto result = doctorService.createDoctor(request);
  assertNotNull(result);
}

// ❌ SAI: Mock quá nhiều, test implementation thay vì behavior
@Test
void testCreateDoctor() {
  // Mock internal methods của class đang test
  DoctorService spyService = spy(doctorService);
  doReturn(true).when(spyService).validateEmail(any());
  doReturn(mockActor).when(spyService).buildActor(any());

  // Test này sẽ break khi refactor internal implementation
}

// ❌ SAI: Không verify interactions quan trọng
@Test
void testCreateDoctor() {
  DoctorDto result = doctorService.createDoctor(request);
  assertNotNull(result);
  // Thiếu verify:
  // - Email notification có được gửi?
  // - Actor có được tạo với đúng params?
}

// ❌ SAI: Test phụ thuộc thứ tự (flaky test)
private static MstDoctor sharedDoctor; // State shared between tests

@Test
void test1_createDoctor() {
  sharedDoctor = doctorService.createDoctor(request);
  // test2 phụ thuộc vào sharedDoctor
}

@Test
void test2_updateDoctor() {
  doctorService.updateDoctorStatus(sharedDoctor.getId(), DoctorStatus.INACTIVE);
  // Fail nếu test1 không chạy trước
}

// ❌ SAI: Assert quá ít
@Test
void testCreateDoctor() {
  DoctorDto result = doctorService.createDoctor(request);
  assertNotNull(result); // Chỉ assert not null, không verify data
}
```

### Phát hiện

```regex
# Tìm test class thiếu @ExtendWith(MockitoExtension.class)
class \w+ServiceTest\s*\{(?!.*@ExtendWith\(MockitoExtension\.class\))

# Tìm test method không có assertion
@Test\s+void\s+\w+\([^)]*\)\s*\{(?:(?!assert|verify).)*\}

# Tìm test không verify mock interactions
@Test\s+void\s+should_\w+_when_\w+\([^)]*\)\s*\{(?:(?!verify\().)*\}
```

### Checklist
- [ ] Mỗi service method có ≥ 1 unit test
- [ ] Test coverage service layer ≥ 80%
- [ ] Sử dụng `@Mock` cho dependencies
- [ ] Sử dụng `@InjectMocks` cho class đang test
- [ ] Test cả happy path và edge cases
- [ ] Verify mock interactions với `verify()`
- [ ] Assertions đầy đủ (data, state, exceptions)
- [ ] Test độc lập, không share state
- [ ] Test naming: `should_doX_when_conditionY`

---

## 09.02: Integration test với @SpringBootTest + TestContainers 🔴

### Metadata
- **Mức độ:** 🔴 BẮT BUỘC
- **Lý do:** Verify tích hợp DB, messaging, external services
- **Công cụ:** @SpringBootTest, TestContainers, REST Assured
- **Phạm vi:** API endpoints, database operations, multi-layer flows

### Tại sao?
1. **Real environment**: Test với database thật (không mock), phát hiện SQL errors
2. **End-to-end flow**: Verify toàn bộ stack từ Controller → Service → Repository
3. **Data integrity**: Kiểm tra constraints, transactions, cascading deletes
4. **Schema validation**: Phát hiện sớm migration issues
5. **External dependencies**: Test tích hợp với message queues, cache, APIs

### ✅ Cách đúng

```java
// ✅ Base integration test configuration
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@Testcontainers
@ActiveProfiles("test")
@Transactional // Rollback sau mỗi test
abstract class BaseIntegrationTest {

  @Container
  static PostgreSQLContainer<?> postgres = new PostgreSQLContainer<>("postgres:15-alpine")
      .withDatabaseName("medicalbox_test")
      .withUsername("test")
      .withPassword("test");

  @DynamicPropertySource
  static void configureProperties(DynamicPropertyRegistry registry) {
    registry.add("spring.datasource.url", postgres::getJdbcUrl);
    registry.add("spring.datasource.username", postgres::getUsername);
    registry.add("spring.datasource.password", postgres::getPassword);
  }

  @Autowired
  protected TestRestTemplate restTemplate;

  @Autowired
  protected ObjectMapper objectMapper;

  @BeforeEach
  void setUp() {
    // Clean database hoặc load test fixtures
  }
}

// ✅ Integration test cho Doctor API
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@Testcontainers
@ActiveProfiles("test")
class DoctorIntegrationTest extends BaseIntegrationTest {

  @Autowired
  private DoctorRepository doctorRepository;

  @Autowired
  private ActorRepository actorRepository;

  @Nested
  @DisplayName("POST /api/doctors")
  class CreateDoctorTests {

    @Test
    void should_createDoctor_and_persistToDatabase() {
      // Given
      CreateDoctorRequest request = new CreateDoctorRequest(
          "Dr. Nguyen Van A",
          "doctor.a@clinic.com",
          1001L
      );

      // Tạo actor trước
      RelActor actor = actorRepository.save(RelActor.builder()
          .actorType(ActorType.CLINIC)
          .actorRefId(1001L)
          .build());

      // When
      ResponseEntity<DoctorDto> response = restTemplate.postForEntity(
          "/api/doctors",
          request,
          DoctorDto.class
      );

      // Then - Verify HTTP response
      assertThat(response.getStatusCode()).isEqualTo(HttpStatus.CREATED);
      assertThat(response.getBody()).isNotNull();
      assertThat(response.getBody().name()).isEqualTo("Dr. Nguyen Van A");
      assertThat(response.getBody().email()).isEqualTo("doctor.a@clinic.com");

      // Then - Verify database persistence
      Long doctorId = response.getBody().id();
      Optional<MstDoctor> savedDoctor = doctorRepository.findById(doctorId);

      assertThat(savedDoctor).isPresent();
      assertThat(savedDoctor.get().getName()).isEqualTo("Dr. Nguyen Van A");
      assertThat(savedDoctor.get().getEmail()).isEqualTo("doctor.a@clinic.com");
      assertThat(savedDoctor.get().getStatus()).isEqualTo(DoctorStatus.ACTIVE);
      assertThat(savedDoctor.get().getActor().getId()).isEqualTo(actor.getId());
    }

    @Test
    void should_returnBadRequest_when_emailAlreadyExists() {
      // Given - Tạo doctor với email đã tồn tại
      MstDoctor existing = doctorRepository.save(MstDoctor.builder()
          .name("Existing Doctor")
          .email("existing@clinic.com")
          .status(DoctorStatus.ACTIVE)
          .build());

      CreateDoctorRequest request = new CreateDoctorRequest(
          "New Doctor",
          "existing@clinic.com", // Email trùng
          1001L
      );

      // When
      ResponseEntity<ErrorResponse> response = restTemplate.postForEntity(
          "/api/doctors",
          request,
          ErrorResponse.class
      );

      // Then
      assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
      assertThat(response.getBody()).isNotNull();
      assertThat(response.getBody().message()).contains("Email đã tồn tại");

      // Verify không tạo record mới
      long count = doctorRepository.count();
      assertThat(count).isEqualTo(1); // Chỉ có existing doctor
    }

    @Test
    void should_rollbackTransaction_when_exceptionOccurs() {
      // Given
      CreateDoctorRequest request = new CreateDoctorRequest(
          "Dr. Exception",
          "exception@clinic.com",
          9999L // actorRefId không tồn tại → exception
      );

      long countBefore = doctorRepository.count();

      // When
      ResponseEntity<ErrorResponse> response = restTemplate.postForEntity(
          "/api/doctors",
          request,
          ErrorResponse.class
      );

      // Then
      assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);

      // Verify transaction rollback
      long countAfter = doctorRepository.count();
      assertThat(countAfter).isEqualTo(countBefore); // Không tăng
    }
  }

  @Nested
  @DisplayName("GET /api/doctors/{id}")
  class GetDoctorTests {

    @Test
    void should_returnDoctor_when_exists() {
      // Given
      MstDoctor doctor = doctorRepository.save(MstDoctor.builder()
          .name("Dr. Test")
          .email("test@clinic.com")
          .status(DoctorStatus.ACTIVE)
          .build());

      // When
      ResponseEntity<DoctorDto> response = restTemplate.getForEntity(
          "/api/doctors/{id}",
          DoctorDto.class,
          doctor.getId()
      );

      // Then
      assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
      assertThat(response.getBody()).isNotNull();
      assertThat(response.getBody().id()).isEqualTo(doctor.getId());
      assertThat(response.getBody().name()).isEqualTo("Dr. Test");
    }

    @Test
    void should_return404_when_doctorNotFound() {
      // When
      ResponseEntity<ErrorResponse> response = restTemplate.getForEntity(
          "/api/doctors/{id}",
          ErrorResponse.class,
          999L
      );

      // Then
      assertThat(response.getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);
    }
  }

  @Nested
  @DisplayName("DELETE /api/doctors/{id}")
  class DeleteDoctorTests {

    @Test
    void should_deleteDoctor_and_cascadeRelations() {
      // Given
      RelActor actor = actorRepository.save(RelActor.builder()
          .actorType(ActorType.CLINIC)
          .actorRefId(1001L)
          .build());

      MstDoctor doctor = doctorRepository.save(MstDoctor.builder()
          .name("Dr. ToDelete")
          .email("delete@clinic.com")
          .actor(actor)
          .status(DoctorStatus.ACTIVE)
          .build());

      Long doctorId = doctor.getId();
      Long actorId = actor.getId();

      // When
      restTemplate.delete("/api/doctors/{id}", doctorId);

      // Then - Verify doctor deleted
      Optional<MstDoctor> deletedDoctor = doctorRepository.findById(doctorId);
      assertThat(deletedDoctor).isEmpty();

      // Then - Verify cascade delete actor (nếu có @OnDelete)
      // Optional<RelActor> deletedActor = actorRepository.findById(actorId);
      // assertThat(deletedActor).isEmpty();
    }
  }
}

// ✅ Integration test với authentication
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@Testcontainers
class SecuredEndpointIntegrationTest extends BaseIntegrationTest {

  @Test
  void should_return401_when_noAuthentication() {
    // When
    ResponseEntity<ErrorResponse> response = restTemplate.getForEntity(
        "/api/doctors",
        ErrorResponse.class
    );

    // Then
    assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
  }

  @Test
  void should_returnData_when_validToken() {
    // Given
    String token = "Bearer eyJhbGciOiJIUzI1Ni..."; // Mock token

    HttpHeaders headers = new HttpHeaders();
    headers.set("Authorization", token);
    HttpEntity<?> entity = new HttpEntity<>(headers);

    // When
    ResponseEntity<DoctorDto[]> response = restTemplate.exchange(
        "/api/doctors",
        HttpMethod.GET,
        entity,
        DoctorDto[].class
    );

    // Then
    assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
  }
}
```

### ❌ Cách sai

```java
// ❌ SAI: Dùng H2 in-memory database thay vì TestContainers
@SpringBootTest
@ActiveProfiles("test")
class DoctorIntegrationTest {
  // application-test.yml:
  // spring.datasource.url=jdbc:h2:mem:testdb

  // Vấn đề:
  // - H2 SQL syntax khác PostgreSQL
  // - Không phát hiện được PostgreSQL-specific issues
  // - JSON/JSONB, array types không tương thích
}

// ❌ SAI: Không cleanup data giữa các tests
@SpringBootTest
@Testcontainers
class DoctorIntegrationTest {
  // Thiếu @Transactional hoặc @DirtiesContext

  @Test
  void test1() {
    doctorRepository.save(doctor1); // Data còn lại sau test
  }

  @Test
  void test2() {
    // Test này bị ảnh hưởng bởi data từ test1 → flaky test
    List<MstDoctor> all = doctorRepository.findAll();
    assertEquals(0, all.size()); // FAIL vì có doctor1
  }
}

// ❌ SAI: Mock dependencies trong integration test
@SpringBootTest
@Testcontainers
class DoctorIntegrationTest {

  @MockBean // ❌ Không nên mock trong integration test
  private NotificationService notificationService;

  @Test
  void testCreateDoctor() {
    // Mất đi mục đích của integration test
    // Nên test end-to-end flow thật
  }
}

// ❌ SAI: Không verify database state
@SpringBootTest
@Testcontainers
class DoctorIntegrationTest {

  @Test
  void testCreateDoctor() {
    ResponseEntity<DoctorDto> response = restTemplate.postForEntity(...);
    assertEquals(HttpStatus.CREATED, response.getStatusCode());

    // ❌ Thiếu verify database:
    // - Record có thực sự được lưu?
    // - Relationships có đúng?
    // - Constraints có được enforce?
  }
}

// ❌ SAI: Hardcode port trong URL
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.DEFINED_PORT)
class DoctorIntegrationTest {

  @Test
  void testCreateDoctor() {
    // ❌ Port conflict khi chạy parallel
    String url = "http://localhost:8080/api/doctors";

    // ✅ Dùng @LocalServerPort hoặc TestRestTemplate
  }
}
```

### Phát hiện

```regex
# Tìm integration test dùng H2 thay vì TestContainers
@SpringBootTest(?!.*@Testcontainers)[\s\S]*?class\s+\w+IntegrationTest

# Tìm integration test thiếu @Transactional hoặc @DirtiesContext
@SpringBootTest\s+class\s+\w+IntegrationTest\s*\{(?!.*(@Transactional|@DirtiesContext))

# Tìm hardcoded localhost:8080
http://localhost:8080/
```

### Checklist
- [ ] Sử dụng `@SpringBootTest` với `RANDOM_PORT`
- [ ] Sử dụng TestContainers cho database
- [ ] Test với database thật (PostgreSQL), không dùng H2
- [ ] Cleanup data sau mỗi test (`@Transactional` hoặc `@DirtiesContext`)
- [ ] Verify HTTP response status
- [ ] Verify database persistence
- [ ] Test transaction rollback khi exception
- [ ] Test authentication/authorization
- [ ] Test cascading deletes/updates
- [ ] Không mock dependencies trong integration test

---

## 09.03: @WebMvcTest cho controller layer (slice test) 🟠

### Metadata
- **Mức độ:** 🟠 KHUYẾN NGHỊ
- **Lý do:** Test nhanh controller layer mà không load full context
- **Công cụ:** @WebMvcTest, MockMvc, @MockBean
- **Phạm vi:** HTTP request/response, validation, error handling

### Tại sao?
1. **Fast**: Chỉ load Spring MVC components, không load DB/messaging
2. **Focused**: Test HTTP layer riêng biệt, dễ debug
3. **Validation**: Verify request validation, response serialization
4. **Error handling**: Test exception handlers, error responses
5. **Security**: Test authentication/authorization rules

### ✅ Cách đúng

```java
// ✅ WebMvcTest cho một controller
@WebMvcTest(DoctorController.class)
class DoctorControllerTest {

  @Autowired
  private MockMvc mockMvc;

  @MockBean
  private DoctorService doctorService;

  @Autowired
  private ObjectMapper objectMapper;

  @Nested
  @DisplayName("POST /api/doctors")
  class CreateDoctorTests {

    @Test
    void should_returnCreated_when_validRequest() throws Exception {
      // Given
      CreateDoctorRequest request = new CreateDoctorRequest(
          "Dr. Nguyen Van A",
          "doctor.a@clinic.com",
          1001L
      );

      DoctorDto expectedResponse = new DoctorDto(
          1L,
          "Dr. Nguyen Van A",
          "doctor.a@clinic.com",
          DoctorStatus.ACTIVE
      );

      when(doctorService.createDoctor(any(CreateDoctorRequest.class)))
          .thenReturn(expectedResponse);

      // When & Then
      mockMvc.perform(post("/api/doctors")
              .contentType(MediaType.APPLICATION_JSON)
              .content(objectMapper.writeValueAsString(request)))
          .andExpect(status().isCreated())
          .andExpect(jsonPath("$.id").value(1))
          .andExpect(jsonPath("$.name").value("Dr. Nguyen Van A"))
          .andExpect(jsonPath("$.email").value("doctor.a@clinic.com"))
          .andExpect(jsonPath("$.status").value("ACTIVE"));

      // Verify service called
      verify(doctorService).createDoctor(any(CreateDoctorRequest.class));
    }

    @Test
    void should_returnBadRequest_when_nameIsBlank() throws Exception {
      // Given
      CreateDoctorRequest request = new CreateDoctorRequest(
          "", // ❌ Blank name
          "doctor@clinic.com",
          1001L
      );

      // When & Then
      mockMvc.perform(post("/api/doctors")
              .contentType(MediaType.APPLICATION_JSON)
              .content(objectMapper.writeValueAsString(request)))
          .andExpect(status().isBadRequest())
          .andExpect(jsonPath("$.errors.name").value("Tên bác sĩ không được để trống"));

      // Verify service không được gọi
      verify(doctorService, never()).createDoctor(any());
    }

    @Test
    void should_returnBadRequest_when_emailInvalid() throws Exception {
      // Given
      CreateDoctorRequest request = new CreateDoctorRequest(
          "Dr. Nguyen Van A",
          "invalid-email", // ❌ Email không hợp lệ
          1001L
      );

      // When & Then
      mockMvc.perform(post("/api/doctors")
              .contentType(MediaType.APPLICATION_JSON)
              .content(objectMapper.writeValueAsString(request)))
          .andExpect(status().isBadRequest())
          .andExpect(jsonPath("$.errors.email").value("Email không hợp lệ"));
    }

    @Test
    void should_returnBadRequest_when_serviceThrowsDuplicateEmailException() throws Exception {
      // Given
      CreateDoctorRequest request = new CreateDoctorRequest(
          "Dr. Nguyen Van A",
          "duplicate@clinic.com",
          1001L
      );

      when(doctorService.createDoctor(any(CreateDoctorRequest.class)))
          .thenThrow(new DuplicateEmailException("Email đã tồn tại"));

      // When & Then
      mockMvc.perform(post("/api/doctors")
              .contentType(MediaType.APPLICATION_JSON)
              .content(objectMapper.writeValueAsString(request)))
          .andExpect(status().isBadRequest())
          .andExpect(jsonPath("$.message").value("Email đã tồn tại"));
    }
  }

  @Nested
  @DisplayName("GET /api/doctors/{id}")
  class GetDoctorTests {

    @Test
    void should_returnDoctor_when_exists() throws Exception {
      // Given
      Long doctorId = 1L;
      DoctorDto expectedResponse = new DoctorDto(
          doctorId,
          "Dr. Test",
          "test@clinic.com",
          DoctorStatus.ACTIVE
      );

      when(doctorService.getDoctorById(doctorId)).thenReturn(expectedResponse);

      // When & Then
      mockMvc.perform(get("/api/doctors/{id}", doctorId))
          .andExpect(status().isOk())
          .andExpect(jsonPath("$.id").value(1))
          .andExpect(jsonPath("$.name").value("Dr. Test"))
          .andExpect(jsonPath("$.email").value("test@clinic.com"));
    }

    @Test
    void should_return404_when_doctorNotFound() throws Exception {
      // Given
      Long doctorId = 999L;
      when(doctorService.getDoctorById(doctorId))
          .thenThrow(new EntityNotFoundException("Doctor not found"));

      // When & Then
      mockMvc.perform(get("/api/doctors/{id}", doctorId))
          .andExpect(status().isNotFound())
          .andExpect(jsonPath("$.message").value("Doctor not found"));
    }
  }

  @Nested
  @DisplayName("PUT /api/doctors/{id}/status")
  class UpdateDoctorStatusTests {

    @Test
    void should_returnNoContent_when_statusUpdated() throws Exception {
      // Given
      Long doctorId = 1L;
      UpdateStatusRequest request = new UpdateStatusRequest(DoctorStatus.INACTIVE);

      // When & Then
      mockMvc.perform(put("/api/doctors/{id}/status", doctorId)
              .contentType(MediaType.APPLICATION_JSON)
              .content(objectMapper.writeValueAsString(request)))
          .andExpect(status().isNoContent());

      verify(doctorService).updateDoctorStatus(doctorId, DoctorStatus.INACTIVE);
    }
  }
}

// ✅ WebMvcTest với authentication
@WebMvcTest(DoctorController.class)
@Import(SecurityConfig.class)
class DoctorControllerSecurityTest {

  @Autowired
  private MockMvc mockMvc;

  @MockBean
  private DoctorService doctorService;

  @Test
  void should_return401_when_noAuthentication() throws Exception {
    mockMvc.perform(get("/api/doctors"))
        .andExpect(status().isUnauthorized());
  }

  @Test
  @WithMockUser(roles = "ADMIN")
  void should_returnData_when_authenticatedAsAdmin() throws Exception {
    when(doctorService.getAllDoctors()).thenReturn(List.of());

    mockMvc.perform(get("/api/doctors"))
        .andExpect(status().isOk());
  }

  @Test
  @WithMockUser(roles = "USER")
  void should_return403_when_insufficientPermissions() throws Exception {
    mockMvc.perform(delete("/api/doctors/{id}", 1L))
        .andExpect(status().isForbidden());
  }
}
```

### ❌ Cách sai

```java
// ❌ SAI: Dùng @SpringBootTest thay vì @WebMvcTest
@SpringBootTest // ❌ Load full context, chậm
class DoctorControllerTest {
  // Mất đi lợi ích của slice test
  // Chạy lâu hơn, phức tạp hơn
}

// ❌ SAI: Test business logic trong controller test
@WebMvcTest(DoctorController.class)
class DoctorControllerTest {

  @Test
  void should_createDoctor_and_sendEmail() throws Exception {
    // ❌ Test business logic (send email) thuộc service layer
    // Controller test chỉ nên verify HTTP interactions

    mockMvc.perform(post("/api/doctors")...)
        .andExpect(status().isCreated());

    // ❌ Không nên verify email sending trong controller test
    verify(emailService).send(...);
  }
}

// ❌ SAI: Không test validation
@WebMvcTest(DoctorController.class)
class DoctorControllerTest {

  @Test
  void testCreateDoctor() throws Exception {
    // ❌ Chỉ test happy path, không test:
    // - Blank name
    // - Invalid email
    // - Null fields

    CreateDoctorRequest request = new CreateDoctorRequest("Dr. A", "a@clinic.com", 1L);
    mockMvc.perform(post("/api/doctors")...)
        .andExpect(status().isCreated());
  }
}

// ❌ SAI: Assert không đầy đủ
@WebMvcTest(DoctorController.class)
class DoctorControllerTest {

  @Test
  void testGetDoctor() throws Exception {
    mockMvc.perform(get("/api/doctors/{id}", 1L))
        .andExpect(status().isOk());

    // ❌ Chỉ check status, không verify response body
    // ❌ Không verify service method được gọi
  }
}

// ❌ SAI: Hardcode JSON strings
@WebMvcTest(DoctorController.class)
class DoctorControllerTest {

  @Test
  void testCreateDoctor() throws Exception {
    String requestJson = "{\"name\":\"Dr. A\",\"email\":\"a@clinic.com\"}"; // ❌

    mockMvc.perform(post("/api/doctors")
        .content(requestJson)); // ❌ Dễ sai, khó maintain

    // ✅ Dùng ObjectMapper.writeValueAsString(request)
  }
}
```

### Phát hiện

```regex
# Tìm controller test dùng @SpringBootTest thay vì @WebMvcTest
@SpringBootTest[\s\S]*?class\s+\w+ControllerTest

# Tìm WebMvcTest thiếu assertions
mockMvc\.perform\([^)]+\)\s*\.andExpect\(status\(\)\.\w+\(\)\);(?![\s\S]*?\.andExpect\(jsonPath)

# Tìm hardcoded JSON strings
\.content\("\\{[^"]*\\}")
```

### Checklist
- [ ] Sử dụng `@WebMvcTest` cho controller tests
- [ ] Mock service dependencies với `@MockBean`
- [ ] Test cả happy path và error cases
- [ ] Verify request validation (`@Valid`, constraints)
- [ ] Verify HTTP status codes
- [ ] Verify JSON response structure (`jsonPath`)
- [ ] Verify service methods được gọi (`verify`)
- [ ] Test authentication/authorization
- [ ] Sử dụng `ObjectMapper` thay vì hardcode JSON
- [ ] Không test business logic trong controller test

---

## 09.04: @DataJpaTest cho repository layer 🟠

### Metadata
- **Mức độ:** 🟠 KHUYẾN NGHỊ
- **Lý do:** Test query methods, custom queries, database constraints
- **Công cụ:** @DataJpaTest, TestEntityManager
- **Phạm vi:** JPA repositories, custom queries, database operations

### Tại sao?
1. **Fast**: Chỉ load JPA components, không load full context
2. **In-memory**: Sử dụng in-memory database (hoặc TestContainers)
3. **Transaction**: Auto-rollback sau mỗi test
4. **Query validation**: Verify JPQL/SQL queries đúng syntax
5. **Constraint testing**: Test unique constraints, foreign keys, nullability

### ✅ Cách đúng

```java
// ✅ DataJpaTest với H2 (nhanh, phù hợp cho simple queries)
@DataJpaTest
class DoctorRepositoryTest {

  @Autowired
  private DoctorRepository doctorRepository;

  @Autowired
  private TestEntityManager entityManager;

  @Nested
  @DisplayName("findByEmail()")
  class FindByEmailTests {

    @Test
    void should_returnDoctor_when_emailExists() {
      // Given
      MstDoctor doctor = MstDoctor.builder()
          .name("Dr. Nguyen Van A")
          .email("doctor.a@clinic.com")
          .status(DoctorStatus.ACTIVE)
          .build();
      entityManager.persistAndFlush(doctor);

      // When
      Optional<MstDoctor> result = doctorRepository.findByEmail("doctor.a@clinic.com");

      // Then
      assertThat(result).isPresent();
      assertThat(result.get().getName()).isEqualTo("Dr. Nguyen Van A");
    }

    @Test
    void should_returnEmpty_when_emailNotExists() {
      // When
      Optional<MstDoctor> result = doctorRepository.findByEmail("nonexistent@clinic.com");

      // Then
      assertThat(result).isEmpty();
    }

    @Test
    void should_beCaseInsensitive() {
      // Given
      MstDoctor doctor = MstDoctor.builder()
          .name("Dr. Test")
          .email("Test@Clinic.COM")
          .status(DoctorStatus.ACTIVE)
          .build();
      entityManager.persistAndFlush(doctor);

      // When
      Optional<MstDoctor> result = doctorRepository.findByEmail("test@clinic.com");

      // Then
      assertThat(result).isPresent();
    }
  }

  @Nested
  @DisplayName("findByStatusAndClinicId()")
  class FindByStatusAndClinicIdTests {

    @Test
    void should_returnActiveDoctorsOnly() {
      // Given
      MstDoctor active1 = createDoctor("Dr. Active 1", DoctorStatus.ACTIVE, 1L);
      MstDoctor active2 = createDoctor("Dr. Active 2", DoctorStatus.ACTIVE, 1L);
      MstDoctor inactive = createDoctor("Dr. Inactive", DoctorStatus.INACTIVE, 1L);

      entityManager.persistAndFlush(active1);
      entityManager.persistAndFlush(active2);
      entityManager.persistAndFlush(inactive);

      // When
      List<MstDoctor> results = doctorRepository.findByStatusAndClinicId(
          DoctorStatus.ACTIVE,
          1L
      );

      // Then
      assertThat(results).hasSize(2);
      assertThat(results).extracting(MstDoctor::getName)
          .containsExactlyInAnyOrder("Dr. Active 1", "Dr. Active 2");
    }

    @Test
    void should_filterByClinicId() {
      // Given
      MstDoctor clinic1 = createDoctor("Dr. Clinic 1", DoctorStatus.ACTIVE, 1L);
      MstDoctor clinic2 = createDoctor("Dr. Clinic 2", DoctorStatus.ACTIVE, 2L);

      entityManager.persistAndFlush(clinic1);
      entityManager.persistAndFlush(clinic2);

      // When
      List<MstDoctor> results = doctorRepository.findByStatusAndClinicId(
          DoctorStatus.ACTIVE,
          1L
      );

      // Then
      assertThat(results).hasSize(1);
      assertThat(results.get(0).getName()).isEqualTo("Dr. Clinic 1");
    }
  }

  @Nested
  @DisplayName("Custom queries")
  class CustomQueryTests {

    @Test
    void should_countActiveDoctorsByClinic() {
      // Given
      entityManager.persistAndFlush(createDoctor("Dr. 1", DoctorStatus.ACTIVE, 1L));
      entityManager.persistAndFlush(createDoctor("Dr. 2", DoctorStatus.ACTIVE, 1L));
      entityManager.persistAndFlush(createDoctor("Dr. 3", DoctorStatus.INACTIVE, 1L));

      // When
      long count = doctorRepository.countActiveDoctorsByClinic(1L);

      // Then
      assertThat(count).isEqualTo(2);
    }

    @Test
    void should_findDoctorsWithUpcomingAppointments() {
      // Given - Setup complex scenario
      MstDoctor doctor = createDoctor("Dr. Busy", DoctorStatus.ACTIVE, 1L);
      entityManager.persistAndFlush(doctor);

      LocalDateTime tomorrow = LocalDateTime.now().plusDays(1);
      TrxAppointment appointment = TrxAppointment.builder()
          .doctor(doctor)
          .scheduledAt(tomorrow)
          .status(AppointmentStatus.SCHEDULED)
          .build();
      entityManager.persistAndFlush(appointment);

      // When
      List<MstDoctor> results = doctorRepository.findDoctorsWithUpcomingAppointments(
          LocalDateTime.now(),
          LocalDateTime.now().plusDays(7)
      );

      // Then
      assertThat(results).hasSize(1);
      assertThat(results.get(0).getName()).isEqualTo("Dr. Busy");
    }
  }

  @Nested
  @DisplayName("Database constraints")
  class ConstraintTests {

    @Test
    void should_throwException_when_emailDuplicate() {
      // Given
      MstDoctor doctor1 = createDoctor("Dr. 1", "same@email.com");
      MstDoctor doctor2 = createDoctor("Dr. 2", "same@email.com");

      entityManager.persistAndFlush(doctor1);

      // When & Then
      assertThatThrownBy(() -> {
        entityManager.persistAndFlush(doctor2);
      }).isInstanceOf(DataIntegrityViolationException.class);
    }

    @Test
    void should_throwException_when_nameIsNull() {
      // Given
      MstDoctor doctor = MstDoctor.builder()
          .name(null) // ❌ NOT NULL constraint
          .email("test@clinic.com")
          .status(DoctorStatus.ACTIVE)
          .build();

      // When & Then
      assertThatThrownBy(() -> {
        entityManager.persistAndFlush(doctor);
      }).isInstanceOf(ConstraintViolationException.class);
    }

    @Test
    void should_cascadeDelete_when_doctorDeleted() {
      // Given
      MstDoctor doctor = createDoctor("Dr. ToDelete", DoctorStatus.ACTIVE, 1L);
      entityManager.persistAndFlush(doctor);

      TrxAppointment appointment = TrxAppointment.builder()
          .doctor(doctor)
          .scheduledAt(LocalDateTime.now())
          .status(AppointmentStatus.SCHEDULED)
          .build();
      entityManager.persistAndFlush(appointment);

      Long appointmentId = appointment.getId();

      // When
      doctorRepository.delete(doctor);
      entityManager.flush();

      // Then - Verify cascade delete
      TrxAppointment deletedAppointment = entityManager.find(TrxAppointment.class, appointmentId);
      assertThat(deletedAppointment).isNull();
    }
  }

  // Helper methods
  private MstDoctor createDoctor(String name, DoctorStatus status, Long clinicId) {
    return MstDoctor.builder()
        .name(name)
        .email(name.toLowerCase().replace(" ", ".") + "@clinic.com")
        .status(status)
        .clinicId(clinicId)
        .build();
  }

  private MstDoctor createDoctor(String name, String email) {
    return MstDoctor.builder()
        .name(name)
        .email(email)
        .status(DoctorStatus.ACTIVE)
        .build();
  }
}

// ✅ DataJpaTest với TestContainers (cho PostgreSQL-specific features)
@DataJpaTest
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
@Testcontainers
class DoctorRepositoryPostgresTest {

  @Container
  static PostgreSQLContainer<?> postgres = new PostgreSQLContainer<>("postgres:15-alpine");

  @DynamicPropertySource
  static void configureProperties(DynamicPropertyRegistry registry) {
    registry.add("spring.datasource.url", postgres::getJdbcUrl);
    registry.add("spring.datasource.username", postgres::getUsername);
    registry.add("spring.datasource.password", postgres::getPassword);
  }

  @Autowired
  private DoctorRepository doctorRepository;

  @Test
  void should_queryJsonbField() {
    // Test PostgreSQL JSONB features
    MstDoctor doctor = MstDoctor.builder()
        .name("Dr. Test")
        .email("test@clinic.com")
        .metadata("{\"specialization\": \"Cardiology\"}")
        .build();

    doctorRepository.save(doctor);

    // Custom query với JSONB
    List<MstDoctor> results = doctorRepository.findByMetadataJsonb("specialization", "Cardiology");
    assertThat(results).hasSize(1);
  }
}
```

### ❌ Cách sai

```java
// ❌ SAI: Dùng @SpringBootTest cho repository tests
@SpringBootTest
class DoctorRepositoryTest {
  // ❌ Load full context, chậm hơn @DataJpaTest
}

// ❌ SAI: Không clear EntityManager cache
@DataJpaTest
class DoctorRepositoryTest {

  @Test
  void testFindById() {
    MstDoctor doctor = createDoctor();
    entityManager.persist(doctor);
    // ❌ Thiếu entityManager.flush()

    Optional<MstDoctor> result = doctorRepository.findById(doctor.getId());
    // Có thể lấy từ cache thay vì database
  }
}

// ❌ SAI: Test quá đơn giản, không có giá trị
@DataJpaTest
class DoctorRepositoryTest {

  @Test
  void testSave() {
    MstDoctor doctor = createDoctor();
    MstDoctor saved = doctorRepository.save(doctor);
    assertNotNull(saved.getId()); // ❌ Test Spring Data JPA, không test logic
  }

  // ✅ Nên test: custom queries, complex filters, constraints
}

// ❌ SAI: Không test edge cases
@DataJpaTest
class DoctorRepositoryTest {

  @Test
  void testFindByEmail() {
    // ❌ Chỉ test happy path, không test:
    // - Email không tồn tại
    // - Case sensitivity
    // - Email null
    // - Email với whitespace
  }
}

// ❌ SAI: Dùng H2 cho PostgreSQL-specific features
@DataJpaTest // ❌ H2 by default
class DoctorRepositoryTest {

  @Test
  void testJsonbQuery() {
    // ❌ H2 không support JSONB
    // ❌ Test này sẽ pass trên H2 nhưng fail trên PostgreSQL production
  }
}
```

### Phát hiện

```regex
# Tìm repository test dùng @SpringBootTest
@SpringBootTest[\s\S]*?class\s+\w+RepositoryTest

# Tìm persist() không có flush()
entityManager\.persist\([^)]+\);(?![\s\S]{0,50}flush\(\))

# Tìm test chỉ assert ID not null (quá đơn giản)
assertThat\(\w+\.getId\(\)\)\.isNotNull\(\);(?![\s\S]{0,100}assertThat)
```

### Checklist
- [ ] Sử dụng `@DataJpaTest` cho repository tests
- [ ] Test custom query methods
- [ ] Test query với multiple conditions
- [ ] Test database constraints (unique, not null, foreign key)
- [ ] Test cascade operations (delete, update)
- [ ] Use `entityManager.flush()` để verify database state
- [ ] Test edge cases (empty results, null values)
- [ ] Dùng TestContainers cho PostgreSQL-specific features
- [ ] Test case sensitivity của queries
- [ ] Verify query performance (N+1 queries)

---

## 09.05: Test coverage ≥ 80% cho business logic 🔴

### Metadata
- **Mức độ:** 🔴 BẮT BUỘC
- **Lý do:** Đảm bảo business logic được test đầy đủ
- **Công cụ:** JaCoCo, SonarQube
- **Phạm vi:** Service layer, domain logic, critical flows

### Tại sao?
1. **Quality gate**: Coverage thấp = nhiều code không được test
2. **Confidence**: Coverage cao = tự tin refactor/deploy
3. **Bug prevention**: Phát hiện sớm logic errors
4. **Documentation**: Test coverage map chỉ ra flow quan trọng
5. **CI/CD**: Block merge nếu coverage giảm

### ✅ Cách đúng

```xml
<!-- pom.xml - JaCoCo plugin -->
<plugin>
  <groupId>org.jacoco</groupId>
  <artifactId>jacoco-maven-plugin</artifactId>
  <version>0.8.11</version>
  <executions>
    <execution>
      <goals>
        <goal>prepare-agent</goal>
      </goals>
    </execution>
    <execution>
      <id>report</id>
      <phase>test</phase>
      <goals>
        <goal>report</goal>
      </goals>
    </execution>
    <execution>
      <id>jacoco-check</id>
      <goals>
        <goal>check</goal>
      </goals>
      <configuration>
        <rules>
          <rule>
            <element>PACKAGE</element>
            <limits>
              <!-- Line coverage ≥ 80% -->
              <limit>
                <counter>LINE</counter>
                <value>COVEREDRATIO</value>
                <minimum>0.80</minimum>
              </limit>
              <!-- Branch coverage ≥ 70% -->
              <limit>
                <counter>BRANCH</counter>
                <value>COVEREDRATIO</value>
                <minimum>0.70</minimum>
              </limit>
            </limits>
          </rule>
        </rules>
      </configuration>
    </execution>
  </executions>
  <configuration>
    <excludes>
      <!-- Exclude DTOs, configs, mappers -->
      <exclude>**/dto/**</exclude>
      <exclude>**/config/**</exclude>
      <exclude>**/mapper/**</exclude>
      <exclude>**/entity/**</exclude>
      <exclude>**/*Application.class</exclude>
    </excludes>
  </configuration>
</plugin>
```

```yaml
# .github/workflows/ci.yml - CI pipeline với coverage check
name: CI

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Set up JDK 21
        uses: actions/setup-java@v3
        with:
          java-version: '21'
          distribution: 'temurin'

      - name: Run tests with coverage
        run: mvn clean verify

      - name: Check coverage
        run: mvn jacoco:check

      - name: Upload coverage to SonarCloud
        env:
          SONAR_TOKEN: ${{ secrets.SONAR_TOKEN }}
        run: |
          mvn sonar:sonar \
            -Dsonar.projectKey=medicalbox \
            -Dsonar.organization=medicalbox \
            -Dsonar.host.url=https://sonarcloud.io

      - name: Upload coverage report
        uses: codecov/codecov-action@v3
        with:
          files: ./target/site/jacoco/jacoco.xml
          fail_ci_if_error: true
```

```java
// ✅ Service với high coverage
@Service
@RequiredArgsConstructor
public class AppointmentService {

  private final AppointmentRepository appointmentRepository;
  private final DoctorRepository doctorRepository;
  private final NotificationService notificationService;

  public AppointmentDto createAppointment(CreateAppointmentRequest request) {
    // Validate doctor exists and active
    MstDoctor doctor = doctorRepository.findById(request.doctorId())
        .orElseThrow(() -> new EntityNotFoundException("Doctor not found"));

    if (doctor.getStatus() != DoctorStatus.ACTIVE) {
      throw new InvalidStatusException("Doctor is not active");
    }

    // Validate time slot available
    LocalDateTime scheduledTime = request.scheduledAt();
    if (scheduledTime.isBefore(LocalDateTime.now())) {
      throw new InvalidTimeException("Cannot schedule appointment in the past");
    }

    boolean isSlotTaken = appointmentRepository.existsByDoctorIdAndScheduledAt(
        request.doctorId(),
        scheduledTime
    );

    if (isSlotTaken) {
      throw new TimeSlotUnavailableException("Time slot already booked");
    }

    // Create appointment
    TrxAppointment appointment = TrxAppointment.builder()
        .doctor(doctor)
        .patientName(request.patientName())
        .scheduledAt(scheduledTime)
        .status(AppointmentStatus.SCHEDULED)
        .build();

    TrxAppointment saved = appointmentRepository.save(appointment);

    // Send notification
    notificationService.sendAppointmentConfirmation(saved);

    return AppointmentMapper.toDto(saved);
  }

  // Nhiều methods khác...
}

// ✅ Test suite với high coverage
@ExtendWith(MockitoExtension.class)
class AppointmentServiceTest {

  @Mock
  private AppointmentRepository appointmentRepository;

  @Mock
  private DoctorRepository doctorRepository;

  @Mock
  private NotificationService notificationService;

  @InjectMocks
  private AppointmentService appointmentService;

  @Nested
  @DisplayName("createAppointment()")
  class CreateAppointmentTests {

    // Test 1: Happy path (20% coverage)
    @Test
    void should_createAppointment_when_validRequest() {
      // ...
    }

    // Test 2: Doctor not found (10% coverage)
    @Test
    void should_throwException_when_doctorNotFound() {
      // ...
    }

    // Test 3: Doctor inactive (10% coverage)
    @Test
    void should_throwException_when_doctorInactive() {
      // ...
    }

    // Test 4: Past time (10% coverage)
    @Test
    void should_throwException_when_scheduledInPast() {
      // ...
    }

    // Test 5: Time slot taken (10% coverage)
    @Test
    void should_throwException_when_timeSlotTaken() {
      // ...
    }

    // Test 6: Notification sent (5% coverage)
    @Test
    void should_sendNotification_when_appointmentCreated() {
      // ...
    }
  }

  // Tổng coverage: 80%+ cho createAppointment()
  // Repeat cho tất cả public methods
}
```

```bash
# ✅ Maven commands
# Run tests với coverage report
mvn clean test

# Generate coverage report
mvn jacoco:report

# View report
open target/site/jacoco/index.html

# Check coverage threshold
mvn jacoco:check

# Fail build nếu coverage < 80%
# (configured in pom.xml)
```

### ❌ Cách sai

```java
// ❌ SAI: Chỉ test happy path
@ExtendWith(MockitoExtension.class)
class AppointmentServiceTest {

  @Test
  void testCreateAppointment() {
    // ❌ Chỉ test case success
    // ❌ Không test:
    //   - Doctor not found
    //   - Doctor inactive
    //   - Past time
    //   - Time slot taken

    // Coverage: chỉ ~30%
  }
}

// ❌ SAI: Test code không có business logic
@Test
void testGetterSetter() {
  AppointmentDto dto = new AppointmentDto();
  dto.setId(1L);
  assertEquals(1L, dto.getId()); // ❌ Waste of time
}

@Test
void testBuilder() {
  Appointment appointment = Appointment.builder()
      .id(1L)
      .status(AppointmentStatus.SCHEDULED)
      .build();

  assertNotNull(appointment); // ❌ Test Lombok, không test logic
}

// ❌ SAI: Exclude quá nhiều classes
```

```xml
<!-- ❌ SAI: Exclude business logic -->
<configuration>
  <excludes>
    <exclude>**/service/**</exclude> <!-- ❌ Đừng exclude service layer! -->
    <exclude>**/controller/**</exclude> <!-- ❌ Controller cũng cần test -->
  </excludes>
</configuration>
```

```java
// ❌ SAI: Fake coverage bằng empty tests
@Test
void testMethod1() {
  // ❌ Empty test chỉ để tăng coverage
  appointmentService.createAppointment(request);
  // Không có assertions!
}

@Test
void testMethod2() throws Exception {
  // ❌ Catch all exceptions để test "pass"
  try {
    appointmentService.createAppointment(invalidRequest);
  } catch (Exception e) {
    // Ignore - ❌ Test pass nhưng không verify behavior
  }
}
```

### Phát hiện

```regex
# Tìm test methods không có assertions
@Test\s+void\s+\w+\([^)]*\)\s*\{(?:(?!assert|verify).)*\}

# Tìm empty try-catch trong tests
try\s*\{[^}]+\}\s*catch\s*\([^)]+\)\s*\{\s*\}

# Tìm test chỉ có assertNotNull
@Test[\s\S]*?assertNotNull\([^)]+\);(?![\s\S]{0,100}assert)
```

### Checklist
- [ ] JaCoCo plugin configured trong `pom.xml`
- [ ] Line coverage ≥ 80% cho service layer
- [ ] Branch coverage ≥ 70%
- [ ] Exclude chỉ DTOs, configs, generated code
- [ ] KHÔNG exclude service/controller layers
- [ ] CI pipeline check coverage trước merge
- [ ] Coverage report uploaded to SonarCloud/Codecov
- [ ] Mỗi public method có ≥ 1 test
- [ ] Test cả happy path và edge cases
- [ ] Test có assertions đầy đủ (không empty tests)

---

## 09.06: Test naming convention: should_doX_when_conditionY 🟡

### Metadata
- **Mức độ:** 🟡 NÊN CÓ
- **Lý do:** Test name là documentation, dễ hiểu behavior
- **Công cụ:** JUnit 5 `@DisplayName`
- **Phạm vi:** Tất cả test methods

### Tại sao?
1. **Self-documenting**: Test name mô tả behavior, không cần đọc code
2. **Readable reports**: Test failures dễ hiểu ngay
3. **Specification**: Test name là spec của feature
4. **Searchable**: Dễ tìm test cho một scenario cụ thể
5. **Team communication**: Giảm thiểu hiểu lầm về requirements

### ✅ Cách đúng

```java
// ✅ Pattern: should_doX_when_conditionY
@ExtendWith(MockitoExtension.class)
class DoctorServiceTest {

  @Nested
  @DisplayName("createDoctor()")
  class CreateDoctorTests {

    @Test
    @DisplayName("should_createDoctor_when_validRequest")
    void should_createDoctor_when_validRequest() {
      // Test implementation
    }

    @Test
    @DisplayName("should_throwDuplicateEmailException_when_emailAlreadyExists")
    void should_throwDuplicateEmailException_when_emailAlreadyExists() {
      // Test implementation
    }

    @Test
    @DisplayName("should_throwValidationException_when_nameIsBlank")
    void should_throwValidationException_when_nameIsBlank() {
      // Test implementation
    }

    @Test
    @DisplayName("should_sendWelcomeEmail_when_doctorCreatedSuccessfully")
    void should_sendWelcomeEmail_when_doctorCreatedSuccessfully() {
      // Test implementation
    }
  }

  @Nested
  @DisplayName("updateDoctorStatus()")
  class UpdateDoctorStatusTests {

    @Test
    @DisplayName("should_updateStatus_when_validRequest")
    void should_updateStatus_when_validRequest() {
      // Test implementation
    }

    @Test
    @DisplayName("should_sendDeactivationEmail_when_statusChangedToInactive")
    void should_sendDeactivationEmail_when_statusChangedToInactive() {
      // Test implementation
    }

    @Test
    @DisplayName("should_notSendEmail_when_statusUnchanged")
    void should_notSendEmail_when_statusUnchanged() {
      // Test implementation
    }

    @Test
    @DisplayName("should_throwEntityNotFoundException_when_doctorNotFound")
    void should_throwEntityNotFoundException_when_doctorNotFound() {
      // Test implementation
    }
  }
}

// ✅ Alternative pattern: given_when_then (BDD style)
@Test
@DisplayName("given_existingEmail_when_createDoctor_then_throwException")
void given_existingEmail_when_createDoctor_then_throwException() {
  // Given
  when(doctorRepository.existsByEmail("existing@clinic.com")).thenReturn(true);

  // When & Then
  assertThatThrownBy(() -> doctorService.createDoctor(request))
      .isInstanceOf(DuplicateEmailException.class);
}

// ✅ Test failure report dễ đọc
/*
DoctorServiceTest > createDoctor() > should_throwDuplicateEmailException_when_emailAlreadyExists FAILED
    Expected: DuplicateEmailException
    Actual: No exception thrown
*/
```

```java
// ✅ Real-world examples
@Nested
@DisplayName("Appointment scheduling")
class AppointmentSchedulingTests {

  @Test
  void should_createAppointment_when_timeSlotAvailable() { }

  @Test
  void should_throwTimeSlotUnavailableException_when_doctorAlreadyBooked() { }

  @Test
  void should_throwInvalidTimeException_when_scheduledInPast() { }

  @Test
  void should_throwEntityNotFoundException_when_doctorNotFound() { }

  @Test
  void should_throwInvalidStatusException_when_doctorInactive() { }

  @Test
  void should_sendConfirmationEmail_when_appointmentCreated() { }

  @Test
  void should_updateDoctorAvailability_when_appointmentCreated() { }
}

@Nested
@DisplayName("Payment processing")
class PaymentProcessingTests {

  @Test
  void should_processPayment_when_validCard() { }

  @Test
  void should_throwInsufficientFundsException_when_balanceTooLow() { }

  @Test
  void should_throwCardExpiredException_when_cardExpired() { }

  @Test
  void should_refundPayment_when_appointmentCancelled() { }

  @Test
  void should_sendPaymentReceipt_when_paymentSuccessful() { }
}
```

### ❌ Cách sai

```java
// ❌ SAI: Test names không mô tả
@Test
void test1() { } // ❌ Không biết test gì

@Test
void testCreateDoctor() { } // ❌ Không biết scenario nào

@Test
void createDoctor_test() { } // ❌ Không meaningful

@Test
void testCase1() { } // ❌ Hoàn toàn vô nghĩa

// ❌ SAI: Tên quá chung chung
@Test
void testSuccess() { } // ❌ Success của gì?

@Test
void testError() { } // ❌ Error gì? Condition gì?

@Test
void testValidation() { } // ❌ Validate field nào?

// ❌ SAI: Tên quá dài, khó đọc
@Test
void testWhenDoctorIsCreatedWithValidNameAndEmailAndStatusThenTheSystemShouldSaveItToDatabaseAndSendWelcomeEmailToTheDoctor() {
  // ❌ Quá dài, khó maintain
}

// ❌ SAI: Không follow convention
@Test
void CreateDoctor_WithValidRequest_ShouldSucceed() { } // ❌ PascalCase

@Test
void SHOULD_CREATE_DOCTOR_WHEN_VALID() { } // ❌ UPPER_CASE

@Test
void create_doctor_success() { } // ❌ Không có "should", "when"

// ❌ SAI: Test failure report khó hiểu
/*
DoctorServiceTest > test1 FAILED
    Expected: DuplicateEmailException
    Actual: No exception thrown

❌ Không biết đang test scenario gì!
*/
```

### Phát hiện

```regex
# Tìm test methods không follow naming convention
@Test\s+void\s+(?!should_|given_)\w+\(

# Tìm test methods tên quá ngắn (< 20 chars)
@Test\s+void\s+\w{1,19}\(

# Tìm test methods dùng "test" prefix
@Test\s+void\s+test[A-Z]\w+\(
```

### Checklist
- [ ] Test names follow `should_doX_when_conditionY` pattern
- [ ] Hoặc `given_when_then` (BDD style)
- [ ] Test names mô tả behavior, không implementation
- [ ] Dùng `@DisplayName` cho nested classes
- [ ] Test names dài đủ để hiểu, nhưng không quá dài
- [ ] Consistent naming trong toàn project
- [ ] Test failures dễ đọc từ CI logs
- [ ] Không dùng "test" prefix
- [ ] Không dùng generic names (test1, testSuccess)
- [ ] Searchable by scenario

---

## 09.07: @Nested classes nhóm test theo scenario 🟡

### Metadata
- **Mức độ:** 🟡 NÊN CÓ
- **Lý do:** Organize tests theo logic groups, dễ navigate
- **Công cụ:** JUnit 5 `@Nested`
- **Phạm vi:** Test classes có nhiều scenarios

### Tại sao?
1. **Organization**: Nhóm related tests lại, dễ tìm
2. **Readability**: Test report có structure rõ ràng
3. **Setup sharing**: Mỗi nested class có own `@BeforeEach`
4. **Scalability**: Dễ thêm tests mới vào đúng group
5. **Documentation**: Structure phản ánh business flows

### ✅ Cách đúng

```java
// ✅ Nested classes theo method
@ExtendWith(MockitoExtension.class)
class DoctorServiceTest {

  @Mock
  private DoctorRepository doctorRepository;

  @Mock
  private ActorService actorService;

  @InjectMocks
  private DoctorService doctorService;

  @Nested
  @DisplayName("createDoctor()")
  class CreateDoctorTests {

    private CreateDoctorRequest validRequest;

    @BeforeEach
    void setUp() {
      validRequest = new CreateDoctorRequest(
          "Dr. Nguyen Van A",
          "doctor.a@clinic.com",
          1001L
      );
    }

    @Test
    void should_createDoctor_when_validRequest() { }

    @Test
    void should_throwException_when_emailAlreadyExists() { }

    @Test
    void should_throwException_when_nameIsBlank() { }

    @Test
    void should_sendWelcomeEmail_when_doctorCreated() { }
  }

  @Nested
  @DisplayName("updateDoctorStatus()")
  class UpdateDoctorStatusTests {

    private MstDoctor existingDoctor;

    @BeforeEach
    void setUp() {
      existingDoctor = MstDoctor.builder()
          .id(1L)
          .name("Dr. Test")
          .email("test@clinic.com")
          .status(DoctorStatus.ACTIVE)
          .build();

      when(doctorRepository.findById(1L)).thenReturn(Optional.of(existingDoctor));
    }

    @Test
    void should_updateStatus_when_validRequest() { }

    @Test
    void should_sendNotification_when_statusChangedToInactive() { }

    @Test
    void should_notSendNotification_when_statusUnchanged() { }

    @Test
    void should_throwException_when_doctorNotFound() { }
  }

  @Nested
  @DisplayName("deletDoctor()")
  class DeleteDoctorTests {

    @Test
    void should_deleteDoctor_when_exists() { }

    @Test
    void should_throwException_when_doctorNotFound() { }

    @Test
    void should_throwException_when_doctorHasActiveAppointments() { }
  }
}

// ✅ Nested classes theo scenario (complex cases)
@ExtendWith(MockitoExtension.class)
class AppointmentServiceTest {

  @Nested
  @DisplayName("Appointment creation")
  class AppointmentCreationTests {

    @Nested
    @DisplayName("Success scenarios")
    class SuccessScenarios {

      @Test
      void should_createAppointment_when_allValid() { }

      @Test
      void should_sendConfirmation_when_appointmentCreated() { }
    }

    @Nested
    @DisplayName("Validation failures")
    class ValidationFailures {

      @Test
      void should_throwException_when_doctorNotFound() { }

      @Test
      void should_throwException_when_doctorInactive() { }

      @Test
      void should_throwException_when_timeSlotTaken() { }

      @Test
      void should_throwException_when_pastTime() { }
    }
  }

  @Nested
  @DisplayName("Appointment cancellation")
  class AppointmentCancellationTests {

    @Nested
    @DisplayName("Within 24 hours")
    class Within24Hours {

      @Test
      void should_cancelWithPenalty_when_within24Hours() { }

      @Test
      void should_refundPartial_when_within24Hours() { }
    }

    @Nested
    @DisplayName("After 24 hours")
    class After24Hours {

      @Test
      void should_cancelWithoutPenalty_when_after24Hours() { }

      @Test
      void should_refundFull_when_after24Hours() { }
    }
  }
}

// ✅ Test report hierarchy
/*
DoctorServiceTest
  ├─ createDoctor()
  │   ├─ should_createDoctor_when_validRequest ✓
  │   ├─ should_throwException_when_emailAlreadyExists ✓
  │   ├─ should_throwException_when_nameIsBlank ✓
  │   └─ should_sendWelcomeEmail_when_doctorCreated ✓
  ├─ updateDoctorStatus()
  │   ├─ should_updateStatus_when_validRequest ✓
  │   ├─ should_sendNotification_when_statusChangedToInactive ✓
  │   └─ should_notSendNotification_when_statusUnchanged ✓
  └─ deleteDoctor()
      ├─ should_deleteDoctor_when_exists ✓
      └─ should_throwException_when_doctorNotFound ✗
*/
```

```java
// ✅ Nested classes với shared setup
@SpringBootTest
@Testcontainers
class DoctorIntegrationTest {

  @Autowired
  private DoctorRepository doctorRepository;

  @Nested
  @DisplayName("CRUD operations")
  class CrudOperations {

    @BeforeEach
    void setUp() {
      // Clean database
      doctorRepository.deleteAll();
    }

    @Test
    void should_createDoctor() { }

    @Test
    void should_updateDoctor() { }

    @Test
    void should_deleteDoctor() { }
  }

  @Nested
  @DisplayName("Query operations")
  class QueryOperations {

    @BeforeEach
    void setUp() {
      // Load test fixtures
      doctorRepository.saveAll(createTestDoctors());
    }

    @Test
    void should_findByEmail() { }

    @Test
    void should_findByStatus() { }

    @Test
    void should_findByClinicId() { }
  }
}
```

### ❌ Cách sai

```java
// ❌ SAI: Flat structure, khó navigate
@ExtendWith(MockitoExtension.class)
class DoctorServiceTest {

  // 50+ tests không có organization
  @Test
  void testCreateDoctor1() { }

  @Test
  void testCreateDoctor2() { }

  @Test
  void testUpdateStatus1() { }

  @Test
  void testUpdateStatus2() { }

  @Test
  void testDelete1() { }

  // ... 45 more tests

  // ❌ Khó tìm test cho một scenario cụ thể
  // ❌ Không rõ method nào có bao nhiêu tests
}

// ❌ SAI: Nested quá sâu, phức tạp
@ExtendWith(MockitoExtension.class)
class DoctorServiceTest {

  @Nested
  class CreateDoctorTests {

    @Nested
    class ValidationTests {

      @Nested
      class EmailValidationTests {

        @Nested
        class FormatValidation {

          @Test
          void testInvalidFormat() { } // ❌ Quá sâu!
        }
      }
    }
  }
}

// ❌ SAI: Nested classes không có semantic meaning
@ExtendWith(MockitoExtension.class)
class DoctorServiceTest {

  @Nested
  class Group1 { } // ❌ Tên vô nghĩa

  @Nested
  class TestSet1 { } // ❌ Không mô tả scenario

  @Nested
  class Part1 { } // ❌ Không clear purpose
}

// ❌ SAI: Duplicate setup code vì không dùng @Nested
@ExtendWith(MockitoExtension.class)
class DoctorServiceTest {

  @Test
  void testCreateDoctor1() {
    // Setup
    CreateDoctorRequest request = new CreateDoctorRequest(...);
    when(...).thenReturn(...);
    // Test
  }

  @Test
  void testCreateDoctor2() {
    // ❌ Duplicate setup
    CreateDoctorRequest request = new CreateDoctorRequest(...);
    when(...).thenReturn(...);
    // Test
  }

  @Test
  void testCreateDoctor3() {
    // ❌ Duplicate setup lần nữa
    CreateDoctorRequest request = new CreateDoctorRequest(...);
    when(...).thenReturn(...);
    // Test
  }

  // ✅ Nên dùng @Nested + @BeforeEach để share setup
}
```

### Phát hiện

```regex
# Tìm test class có > 10 tests nhưng không có @Nested
class\s+\w+Test\s*\{[\s\S]*?(@Test[\s\S]*?){10,}(?!.*@Nested)

# Tìm nested class không có @DisplayName
@Nested\s+class\s+\w+\s*\{(?!.*@DisplayName)

# Tìm nested class có tên generic
@Nested[\s\S]*?class\s+(Group|Test|Part)\d+\s*\{
```

### Checklist
- [ ] Test class có ≥ 3 methods → use `@Nested`
- [ ] Mỗi `@Nested` class có `@DisplayName`
- [ ] Nested classes nhóm theo method hoặc scenario
- [ ] Shared setup trong `@BeforeEach` của nested class
- [ ] Không nest quá sâu (max 2 levels)
- [ ] Nested class names có semantic meaning
- [ ] Test report hierarchy rõ ràng
- [ ] Dễ navigate và tìm tests
- [ ] Mỗi nested class có 3-10 tests
- [ ] Structure phản ánh business logic

---

## 09.08: Không mock everything — test behavior, không test implementation 🟠

### Metadata
- **Mức độ:** 🟠 KHUYẾN NGHỊ
- **Lý do:** Over-mocking làm tests brittle, không phát hiện real bugs
- **Công cụ:** Mockito, real objects khi có thể
- **Phạm vi:** Unit tests, integration tests

### Tại sao?
1. **Brittle tests**: Mock quá nhiều → tests break khi refactor
2. **False confidence**: Tests pass nhưng production fail
3. **Real bugs**: Mock không phát hiện integration issues
4. **Maintenance cost**: Mỗi lần refactor phải update mocks
5. **Test clarity**: Real objects dễ hiểu hơn mock setup

### ✅ Cách đúng

```java
// ✅ Mock external dependencies, use real value objects
@ExtendWith(MockitoExtension.class)
class DoctorServiceTest {

  @Mock
  private DoctorRepository doctorRepository; // ✅ Mock I/O

  @Mock
  private NotificationService notificationService; // ✅ Mock external service

  @InjectMocks
  private DoctorService doctorService;

  // ✅ KHÔNG mock ActorService nếu nó chỉ là logic wrapper
  // Inject real instance thay vì mock
  private ActorService actorService = new ActorService();

  @Test
  void should_createDoctor_when_validRequest() {
    // ✅ Use real request object (value object)
    CreateDoctorRequest request = new CreateDoctorRequest(
        "Dr. Nguyen Van A",
        "doctor.a@clinic.com",
        1001L
    );

    // ✅ Use real entity builder (no need to mock)
    MstDoctor expectedDoctor = MstDoctor.builder()
        .id(1L)
        .name("Dr. Nguyen Van A")
        .email("doctor.a@clinic.com")
        .status(DoctorStatus.ACTIVE)
        .build();

    // ✅ Mock chỉ external I/O
    when(doctorRepository.existsByEmail(request.email())).thenReturn(false);
    when(doctorRepository.save(any(MstDoctor.class))).thenReturn(expectedDoctor);

    // When
    DoctorDto result = doctorService.createDoctor(request);

    // Then - Test behavior
    assertThat(result.name()).isEqualTo("Dr. Nguyen Van A");
    assertThat(result.email()).isEqualTo("doctor.a@clinic.com");

    // ✅ Verify interactions với external dependencies
    verify(doctorRepository).save(any(MstDoctor.class));
    verify(notificationService).sendWelcomeEmail("doctor.a@clinic.com");
  }
}

// ✅ Test behavior, không test implementation details
@Test
void should_calculateTotalPrice_when_multipleItems() {
  // ✅ Test public behavior
  ShoppingCart cart = new ShoppingCart();
  cart.addItem(new Item("Product A", 100.0, 2));
  cart.addItem(new Item("Product B", 50.0, 1));

  double total = cart.calculateTotal();

  // ✅ Assert on outcome, không assert internal state
  assertThat(total).isEqualTo(250.0);

  // ❌ KHÔNG verify internal methods
  // verify(cart).sumItemPrices(); // Implementation detail!
}

// ✅ Use test fixtures cho complex objects
@ExtendWith(MockitoExtension.class)
class AppointmentServiceTest {

  @Mock
  private AppointmentRepository appointmentRepository;

  @InjectMocks
  private AppointmentService appointmentService;

  // ✅ Real test fixture builder
  private AppointmentFixture fixture = new AppointmentFixture();

  @Test
  void should_createAppointment_when_validRequest() {
    // ✅ Use real fixture data
    CreateAppointmentRequest request = fixture.createValidRequest();
    MstDoctor doctor = fixture.createActiveDoctor();

    when(doctorRepository.findById(request.doctorId()))
        .thenReturn(Optional.of(doctor));

    // Test behavior
    AppointmentDto result = appointmentService.createAppointment(request);

    assertThat(result.doctorId()).isEqualTo(doctor.getId());
  }
}

// ✅ Test fixture builder
class AppointmentFixture {

  public CreateAppointmentRequest createValidRequest() {
    return new CreateAppointmentRequest(
        1L, // doctorId
        "Nguyen Van A",
        LocalDateTime.now().plusDays(1)
    );
  }

  public MstDoctor createActiveDoctor() {
    return MstDoctor.builder()
        .id(1L)
        .name("Dr. Test")
        .email("test@clinic.com")
        .status(DoctorStatus.ACTIVE)
        .build();
  }

  public MstDoctor createInactiveDoctor() {
    return MstDoctor.builder()
        .id(2L)
        .name("Dr. Inactive")
        .status(DoctorStatus.INACTIVE)
        .build();
  }
}
```

```java
// ✅ Integration test: Không mock gì cả
@SpringBootTest
@Testcontainers
class DoctorIntegrationTest {

  @Autowired
  private DoctorService doctorService; // ✅ Real service

  @Autowired
  private DoctorRepository doctorRepository; // ✅ Real repository

  // ✅ Real database via TestContainers
  @Container
  static PostgreSQLContainer<?> postgres = new PostgreSQLContainer<>("postgres:15-alpine");

  @Test
  void should_createDoctor_endToEnd() {
    // ✅ Test toàn bộ stack, không mock
    CreateDoctorRequest request = new CreateDoctorRequest(
        "Dr. Nguyen Van A",
        "doctor.a@clinic.com",
        1001L
    );

    DoctorDto result = doctorService.createDoctor(request);

    // Verify database persistence
    Optional<MstDoctor> saved = doctorRepository.findById(result.id());
    assertThat(saved).isPresent();
  }
}
```

### ❌ Cách sai

```java
// ❌ SAI: Mock everything, kể cả value objects
@ExtendWith(MockitoExtension.class)
class DoctorServiceTest {

  @Mock
  private DoctorRepository doctorRepository;

  @Mock
  private CreateDoctorRequest request; // ❌ Đừng mock DTOs!

  @Mock
  private MstDoctor doctor; // ❌ Đừng mock entities!

  @Mock
  private DoctorDto dto; // ❌ Đừng mock response DTOs!

  @InjectMocks
  private DoctorService doctorService;

  @Test
  void testCreateDoctor() {
    // ❌ Mock everything
    when(request.name()).thenReturn("Dr. A");
    when(request.email()).thenReturn("a@clinic.com");
    when(doctor.getId()).thenReturn(1L);
    when(doctor.getName()).thenReturn("Dr. A");
    when(dto.id()).thenReturn(1L);

    // ❌ Test trở nên vô nghĩa vì mock quá nhiều
    // ❌ Không test logic thật
  }
}

// ❌ SAI: Test implementation details
@ExtendWith(MockitoExtension.class)
class ShoppingCartTest {

  @InjectMocks
  private ShoppingCart cart;

  @Test
  void testCalculateTotal() {
    // ❌ Spy internal methods
    ShoppingCart spyCart = spy(cart);
    doReturn(100.0).when(spyCart).sumItemPrices();
    doReturn(10.0).when(spyCart).calculateTax();

    double total = spyCart.calculateTotal();

    // ❌ Test pass nhưng không test logic thật
    // ❌ Khi refactor internal methods → test break
  }
}

// ❌ SAI: Mock collaborators có business logic
@ExtendWith(MockitoExtension.class)
class AppointmentServiceTest {

  @Mock
  private AppointmentRepository appointmentRepository;

  @Mock
  private DoctorService doctorService; // ❌ Đừng mock service khác!

  @Mock
  private TimeSlotValidator timeSlotValidator; // ❌ Đừng mock validators!

  @InjectMocks
  private AppointmentService appointmentService;

  @Test
  void testCreateAppointment() {
    // ❌ Mock tất cả logic → không test integration
    when(doctorService.findById(1L)).thenReturn(mockDoctor);
    when(timeSlotValidator.isAvailable(...)).thenReturn(true);

    // ❌ Test này không phát hiện bugs trong doctor/validator logic
  }
}

// ❌ SAI: Verify internal method calls
@Test
void testCreateDoctor() {
  doctorService.createDoctor(request);

  // ❌ Verify implementation details
  verify(doctorService).validateEmail(request.email());
  verify(doctorService).buildDoctorEntity(request);
  verify(doctorService).persistDoctor(any());

  // ❌ Tests break khi refactor internal methods
  // ✅ Nên verify public behavior và external interactions
}

// ❌ SAI: Mock chains
@Test
void testGetDoctorName() {
  // ❌ Mock chain quá dài
  when(doctorRepository.findById(1L).get().getName()).thenReturn("Dr. A");

  // ❌ Brittle, khó maintain
  // ✅ Dùng real objects thay vì mock chains
}
```

### Phát hiện

```regex
# Tìm mock DTOs/entities
@Mock[\s\S]*?(Request|Response|Dto|Entity)\s+\w+;

# Tìm spy() usage
spy\(

# Tìm verify internal methods
verify\(\w+\)\.\w+\([^)]*\);(?=[\s\S]*?private\s+\w+\s+\w+\()
```

### Checklist
- [ ] Mock chỉ external dependencies (DB, APIs, messaging)
- [ ] KHÔNG mock value objects (DTOs, requests, responses)
- [ ] KHÔNG mock entities/domain objects
- [ ] KHÔNG mock collaborators có business logic
- [ ] KHÔNG spy() internal methods
- [ ] Test public behavior, không test implementation
- [ ] Use real fixtures cho test data
- [ ] Integration tests không mock gì
- [ ] Verify external interactions, không verify internal calls
- [ ] Tests survive refactoring

---

## 09.09: Test data builders / fixtures tái sử dụng 🟡

### Metadata
- **Mức độ:** 🟡 NÊN CÓ
- **Lý do:** Reduce duplication, dễ maintain test data
- **Công cụ:** Builder pattern, factory methods
- **Phạm vi:** Tất cả test classes

### Tại sao?
1. **DRY**: Không duplicate test data setup
2. **Readability**: Test code ngắn gọn, focus vào logic
3. **Maintainability**: Change test data ở một chỗ
4. **Consistency**: Test data consistent across tests
5. **Productivity**: Tạo test data nhanh hơn

### ✅ Cách đúng

```java
// ✅ Test data builder
public class DoctorTestBuilder {

  private Long id = 1L;
  private String name = "Dr. Nguyen Van A";
  private String email = "doctor.a@clinic.com";
  private DoctorStatus status = DoctorStatus.ACTIVE;
  private Long clinicId = 1001L;
  private RelActor actor;

  public DoctorTestBuilder withId(Long id) {
    this.id = id;
    return this;
  }

  public DoctorTestBuilder withName(String name) {
    this.name = name;
    return this;
  }

  public DoctorTestBuilder withEmail(String email) {
    this.email = email;
    return this;
  }

  public DoctorTestBuilder withStatus(DoctorStatus status) {
    this.status = status;
    return this;
  }

  public DoctorTestBuilder inactive() {
    this.status = DoctorStatus.INACTIVE;
    return this;
  }

  public DoctorTestBuilder withClinicId(Long clinicId) {
    this.clinicId = clinicId;
    return this;
  }

  public DoctorTestBuilder withActor(RelActor actor) {
    this.actor = actor;
    return this;
  }

  public MstDoctor build() {
    return MstDoctor.builder()
        .id(id)
        .name(name)
        .email(email)
        .status(status)
        .clinicId(clinicId)
        .actor(actor)
        .build();
  }

  public static DoctorTestBuilder aDoctor() {
    return new DoctorTestBuilder();
  }

  public static DoctorTestBuilder anInactiveDoctor() {
    return new DoctorTestBuilder().inactive();
  }
}

// ✅ Usage trong tests
@ExtendWith(MockitoExtension.class)
class DoctorServiceTest {

  @Test
  void should_createDoctor_when_validRequest() {
    // ✅ Concise, readable
    MstDoctor doctor = aDoctor()
        .withName("Dr. Custom Name")
        .withEmail("custom@clinic.com")
        .build();

    // Test logic...
  }

  @Test
  void should_throwException_when_doctorInactive() {
    // ✅ Semantic method
    MstDoctor doctor = anInactiveDoctor().build();

    // Test logic...
  }

  @Test
  void should_filterByClinic() {
    // ✅ Easy to create multiple test data
    MstDoctor doctor1 = aDoctor().withClinicId(1L).build();
    MstDoctor doctor2 = aDoctor().withClinicId(1L).build();
    MstDoctor doctor3 = aDoctor().withClinicId(2L).build();

    // Test logic...
  }
}
```

```java
// ✅ Fixture class cho complex scenarios
public class AppointmentTestFixture {

  // Factory methods
  public static CreateAppointmentRequest createValidRequest() {
    return new CreateAppointmentRequest(
        1L, // doctorId
        "Nguyen Van A",
        LocalDateTime.now().plusDays(1)
    );
  }

  public static CreateAppointmentRequest createPastTimeRequest() {
    return new CreateAppointmentRequest(
        1L,
        "Nguyen Van A",
        LocalDateTime.now().minusDays(1) // Past time
    );
  }

  public static MstDoctor createActiveDoctor() {
    return MstDoctor.builder()
        .id(1L)
        .name("Dr. Active")
        .email("active@clinic.com")
        .status(DoctorStatus.ACTIVE)
        .build();
  }

  public static MstDoctor createInactiveDoctor() {
    return MstDoctor.builder()
        .id(2L)
        .name("Dr. Inactive")
        .email("inactive@clinic.com")
        .status(DoctorStatus.INACTIVE)
        .build();
  }

  public static TrxAppointment createScheduledAppointment(MstDoctor doctor) {
    return TrxAppointment.builder()
        .doctor(doctor)
        .patientName("Patient A")
        .scheduledAt(LocalDateTime.now().plusDays(1))
        .status(AppointmentStatus.SCHEDULED)
        .build();
  }

  public static TrxAppointment createCompletedAppointment(MstDoctor doctor) {
    return TrxAppointment.builder()
        .doctor(doctor)
        .patientName("Patient B")
        .scheduledAt(LocalDateTime.now().minusDays(1))
        .status(AppointmentStatus.COMPLETED)
        .build();
  }
}

// ✅ Usage
@ExtendWith(MockitoExtension.class)
class AppointmentServiceTest {

  @Test
  void should_createAppointment_when_validRequest() {
    // ✅ Clean, readable
    CreateAppointmentRequest request = createValidRequest();
    MstDoctor doctor = createActiveDoctor();

    when(doctorRepository.findById(1L)).thenReturn(Optional.of(doctor));

    // Test logic...
  }

  @Test
  void should_throwException_when_pastTime() {
    CreateAppointmentRequest request = createPastTimeRequest();

    // Test logic...
  }
}
```

```java
// ✅ Mother Object pattern
public class DoctorMother {

  public static MstDoctor typical() {
    return MstDoctor.builder()
        .id(1L)
        .name("Dr. Nguyen Van A")
        .email("doctor.a@clinic.com")
        .status(DoctorStatus.ACTIVE)
        .clinicId(1001L)
        .build();
  }

  public static MstDoctor inactive() {
    return typical().toBuilder()
        .status(DoctorStatus.INACTIVE)
        .build();
  }

  public static MstDoctor withoutEmail() {
    return typical().toBuilder()
        .email(null)
        .build();
  }

  public static MstDoctor fromClinic(Long clinicId) {
    return typical().toBuilder()
        .clinicId(clinicId)
        .build();
  }
}

// ✅ Usage
@Test
void should_createDoctor_when_typical() {
  MstDoctor doctor = DoctorMother.typical();
  // Test logic...
}

@Test
void should_throwException_when_inactive() {
  MstDoctor doctor = DoctorMother.inactive();
  // Test logic...
}
```

```java
// ✅ Shared fixture file
// src/test/resources/fixtures/doctors.json
[
  {
    "id": 1,
    "name": "Dr. Nguyen Van A",
    "email": "doctor.a@clinic.com",
    "status": "ACTIVE",
    "clinicId": 1001
  },
  {
    "id": 2,
    "name": "Dr. Tran Thi B",
    "email": "doctor.b@clinic.com",
    "status": "INACTIVE",
    "clinicId": 1002
  }
]

// ✅ Fixture loader
public class FixtureLoader {

  private static final ObjectMapper objectMapper = new ObjectMapper();

  public static <T> List<T> loadFixtures(String filename, Class<T> clazz) {
    try {
      InputStream is = FixtureLoader.class.getResourceAsStream("/fixtures/" + filename);
      return objectMapper.readValue(is, objectMapper.getTypeFactory()
          .constructCollectionType(List.class, clazz));
    } catch (IOException e) {
      throw new RuntimeException("Failed to load fixtures: " + filename, e);
    }
  }
}

// ✅ Usage
@Test
void should_queryMultipleDoctors() {
  List<MstDoctor> doctors = FixtureLoader.loadFixtures("doctors.json", MstDoctor.class);
  doctorRepository.saveAll(doctors);

  // Test logic...
}
```

### ❌ Cách sai

```java
// ❌ SAI: Duplicate test data setup
@ExtendWith(MockitoExtension.class)
class DoctorServiceTest {

  @Test
  void test1() {
    // ❌ Duplicate setup
    MstDoctor doctor = MstDoctor.builder()
        .id(1L)
        .name("Dr. Nguyen Van A")
        .email("doctor.a@clinic.com")
        .status(DoctorStatus.ACTIVE)
        .clinicId(1001L)
        .build();

    // Test logic...
  }

  @Test
  void test2() {
    // ❌ Duplicate setup lại
    MstDoctor doctor = MstDoctor.builder()
        .id(1L)
        .name("Dr. Nguyen Van A")
        .email("doctor.a@clinic.com")
        .status(DoctorStatus.ACTIVE)
        .clinicId(1001L)
        .build();

    // Test logic...
  }

  @Test
  void test3() {
    // ❌ Duplicate setup lần 3
    MstDoctor doctor = MstDoctor.builder()
        .id(1L)
        .name("Dr. Nguyen Van A")
        .email("doctor.a@clinic.com")
        .status(DoctorStatus.ACTIVE)
        .clinicId(1001L)
        .build();

    // Test logic...
  }

  // ✅ Nên dùng builder hoặc fixture
}

// ❌ SAI: Hardcoded test data
@Test
void testCreateDoctor() {
  // ❌ Magic values
  MstDoctor doctor = new MstDoctor(1L, "Dr. A", "a@c.com", 1, 1001L, null);

  // ❌ Khó đọc, khó maintain
}

// ❌ SAI: Test data không realistic
@Test
void testCreateDoctor() {
  // ❌ Test data không realistic
  MstDoctor doctor = MstDoctor.builder()
      .id(1L)
      .name("A") // ❌ Tên quá ngắn
      .email("a") // ❌ Email invalid
      .status(DoctorStatus.ACTIVE)
      .build();

  // Test pass nhưng không phản ánh production data
}

// ❌ SAI: Builder quá phức tạp
public class DoctorTestBuilder {

  // ❌ Quá nhiều logic trong builder
  public DoctorTestBuilder withRandomData() {
    this.id = new Random().nextLong();
    this.name = UUID.randomUUID().toString();
    this.email = generateRandomEmail();
    return this;
  }

  // ❌ Builder có side effects
  public DoctorTestBuilder persist() {
    repository.save(this.build()); // ❌ Side effect!
    return this;
  }

  // ✅ Builder chỉ nên build objects, không có I/O
}
```

### Phát hiện

```regex
# Tìm duplicate builder patterns
MstDoctor\.builder\(\)[\s\S]{100,}\.build\(\);[\s\S]{0,500}MstDoctor\.builder\(\)[\s\S]{100,}\.build\(\);

# Tìm hardcoded test data
new\s+Mst\w+\([^)]*1L[^)]*"[^"]{1,3}"

# Tìm magic values trong tests
@Test[\s\S]*?new\s+\w+\([^)]*\d+L,\s*"[^"]+",\s*\d+
```

### Checklist
- [ ] Test data builders cho main entities
- [ ] Factory methods cho common scenarios
- [ ] Fixture files cho complex test data
- [ ] Builders fluent, chainable
- [ ] Default values realistic
- [ ] No side effects trong builders
- [ ] Shared fixtures across test classes
- [ ] Builders trong `src/test/java/fixtures/`
- [ ] No duplicate test data setup
- [ ] Test data readable và maintainable

---

## 09.10: CI pipeline chạy tests tự động trước merge 🔴

### Metadata
- **Mức độ:** 🔴 BẮT BUỘC
- **Lý do:** Prevent broken code vào main branch
- **Công cụ:** GitHub Actions, GitLab CI, Jenkins
- **Phạm vi:** Tất cả PRs/MRs

### Tại sao?
1. **Quality gate**: Block merge nếu tests fail
2. **Fast feedback**: Phát hiện bugs ngay sau commit
3. **Confidence**: Main branch luôn stable
4. **Team collaboration**: Không block team members với broken code
5. **Automation**: Không phụ thuộc manual testing

### ✅ Cách đúng

```yaml
# ✅ .github/workflows/ci.yml - Comprehensive CI pipeline
name: CI

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main, develop]

jobs:
  test:
    name: Run tests
    runs-on: ubuntu-latest

    services:
      postgres:
        image: postgres:15-alpine
        env:
          POSTGRES_DB: medicalbox_test
          POSTGRES_USER: test
          POSTGRES_PASSWORD: test
        ports:
          - 5432:5432
        options: >-
          --health-cmd pg_isready
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5

    steps:
      - name: Checkout code
        uses: actions/checkout@v3

      - name: Set up JDK 21
        uses: actions/setup-java@v3
        with:
          java-version: '21'
          distribution: 'temurin'
          cache: 'maven'

      - name: Run unit tests
        run: mvn test -Dspring.profiles.active=test

      - name: Run integration tests
        run: mvn verify -Pintegration-test
        env:
          SPRING_DATASOURCE_URL: jdbc:postgresql://localhost:5432/medicalbox_test
          SPRING_DATASOURCE_USERNAME: test
          SPRING_DATASOURCE_PASSWORD: test

      - name: Generate coverage report
        run: mvn jacoco:report

      - name: Check coverage threshold
        run: mvn jacoco:check
        continue-on-error: false

      - name: Upload coverage to Codecov
        uses: codecov/codecov-action@v3
        with:
          files: ./target/site/jacoco/jacoco.xml
          fail_ci_if_error: true

      - name: SonarCloud Scan
        env:
          SONAR_TOKEN: ${{ secrets.SONAR_TOKEN }}
        run: |
          mvn sonar:sonar \
            -Dsonar.projectKey=medicalbox \
            -Dsonar.organization=medicalbox \
            -Dsonar.host.url=https://sonarcloud.io \
            -Dsonar.coverage.jacoco.xmlReportPaths=target/site/jacoco/jacoco.xml

      - name: Upload test results
        if: always()
        uses: actions/upload-artifact@v3
        with:
          name: test-results
          path: target/surefire-reports/

  build:
    name: Build application
    runs-on: ubuntu-latest
    needs: test

    steps:
      - name: Checkout code
        uses: actions/checkout@v3

      - name: Set up JDK 21
        uses: actions/setup-java@v3
        with:
          java-version: '21'
          distribution: 'temurin'
          cache: 'maven'

      - name: Build with Maven
        run: mvn clean package -DskipTests

      - name: Upload artifact
        uses: actions/upload-artifact@v3
        with:
          name: medicalbox-api
          path: target/*.jar
```

```yaml
# ✅ .github/workflows/quality-gate.yml - Enforce quality standards
name: Quality Gate

on:
  pull_request:
    branches: [main]

jobs:
  quality-check:
    name: Quality gate
    runs-on: ubuntu-latest

    steps:
      - name: Checkout code
        uses: actions/checkout@v3
        with:
          fetch-depth: 0 # Full history for SonarCloud

      - name: Set up JDK 21
        uses: actions/setup-java@v3
        with:
          java-version: '21'
          distribution: 'temurin'
          cache: 'maven'

      - name: Run tests with coverage
        run: mvn clean verify

      - name: SonarCloud Quality Gate
        env:
          SONAR_TOKEN: ${{ secrets.SONAR_TOKEN }}
        run: |
          mvn sonar:sonar \
            -Dsonar.projectKey=medicalbox \
            -Dsonar.organization=medicalbox \
            -Dsonar.host.url=https://sonarcloud.io \
            -Dsonar.qualitygate.wait=true

      - name: Check quality gate status
        run: |
          # Fail if quality gate failed
          if [ $? -ne 0 ]; then
            echo "Quality gate failed!"
            exit 1
          fi
```

```yaml
# ✅ Branch protection rules (GitHub Settings)
# Settings > Branches > Branch protection rules for 'main'
# - Require pull request reviews before merging
# - Require status checks to pass before merging:
#   ✓ test
#   ✓ build
#   ✓ quality-check
# - Require branches to be up to date before merging
# - Do not allow bypassing the above settings
```

```xml
<!-- ✅ pom.xml - Maven profiles cho CI -->
<profiles>
  <profile>
    <id>integration-test</id>
    <build>
      <plugins>
        <plugin>
          <groupId>org.apache.maven.plugins</groupId>
          <artifactId>maven-failsafe-plugin</artifactId>
          <version>3.0.0-M9</version>
          <executions>
            <execution>
              <goals>
                <goal>integration-test</goal>
                <goal>verify</goal>
              </goals>
            </execution>
          </executions>
        </plugin>
      </plugins>
    </build>
  </profile>

  <profile>
    <id>ci</id>
    <properties>
      <!-- Faster builds in CI -->
      <maven.test.failure.ignore>false</maven.test.failure.ignore>
      <skipITs>false</skipITs>
    </properties>
  </profile>
</profiles>
```

```yaml
# ✅ .github/dependabot.yml - Auto-update dependencies
version: 2
updates:
  - package-ecosystem: "maven"
    directory: "/"
    schedule:
      interval: "weekly"
    open-pull-requests-limit: 5
    reviewers:
      - "team/backend"
    labels:
      - "dependencies"
      - "automerge"
```

```bash
# ✅ Local pre-commit hook
# .git/hooks/pre-commit
#!/bin/bash

echo "Running tests before commit..."

mvn test

if [ $? -ne 0 ]; then
  echo "❌ Tests failed! Commit aborted."
  exit 1
fi

echo "✅ Tests passed. Proceeding with commit."
```

### ❌ Cách sai

```yaml
# ❌ SAI: CI không chạy tests
name: CI

on: [push]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Build
        run: mvn package -DskipTests # ❌ Skip tests!

  # ❌ Không có test job
  # ❌ Không check coverage
  # ❌ Không có quality gate
```

```yaml
# ❌ SAI: CI chạy tests nhưng không fail on error
name: CI

on: [push]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: Run tests
        run: mvn test
        continue-on-error: true # ❌ Ignore failures!

  # ❌ Tests fail nhưng CI vẫn pass → broken code vào main
```

```yaml
# ❌ SAI: Không có branch protection
# Settings > Branches > (No protection rules)

# ❌ Developers có thể:
# - Push trực tiếp lên main
# - Merge PR mà tests fail
# - Bypass reviews
```

```yaml
# ❌ SAI: CI chỉ chạy trên main, không chạy trên PRs
name: CI

on:
  push:
    branches: [main] # ❌ Chỉ main

# ❌ PRs không được test trước merge
# ❌ Phát hiện bugs quá muộn
```

```yaml
# ❌ SAI: CI quá chậm
name: CI

on: [push]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: Run all tests sequentially
        run: |
          mvn test # ❌ 10 phút
          mvn verify # ❌ 15 phút
          mvn site # ❌ 5 phút
        # Tổng: 30 phút → developers không chờ

  # ✅ Nên:
  # - Chạy unit tests nhanh trước (< 2 phút)
  # - Integration tests parallel
  # - Cache dependencies
```

```yaml
# ❌ SAI: Không upload test results
name: CI

on: [push]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: Run tests
        run: mvn test

  # ❌ Test fails → không có artifacts để debug
  # ❌ Không có coverage report
  # ❌ Không có test trends
```

### Phát hiện

```regex
# Tìm CI config skip tests
-DskipTests

# Tìm continue-on-error: true
continue-on-error:\s*true

# Tìm mvn commands không có test
mvn\s+(?!test|verify)
```

### Checklist
- [ ] CI pipeline configured (GitHub Actions/GitLab CI/Jenkins)
- [ ] CI chạy trên mọi PR/MR
- [ ] Unit tests chạy trước integration tests
- [ ] Tests PHẢI pass để merge (không `continue-on-error`)
- [ ] Coverage report generated và checked
- [ ] SonarCloud quality gate enforced
- [ ] Branch protection rules enabled
- [ ] Test results uploaded (artifacts)
- [ ] CI feedback < 5 phút (unit tests)
- [ ] Pre-commit hooks chạy tests locally
- [ ] Dependabot auto-updates dependencies
- [ ] CI cache dependencies (Maven/Gradle cache)
- [ ] Parallel test execution
- [ ] TestContainers trong CI
- [ ] Không skip tests trong CI

---

## Tổng kết

### Coverage targets
| Layer | Line Coverage | Branch Coverage |
|-------|--------------|-----------------|
| Service | ≥ 80% | ≥ 70% |
| Controller | ≥ 70% | ≥ 60% |
| Repository | ≥ 60% | ≥ 50% |
| Overall | ≥ 80% | ≥ 70% |

### Test pyramid
```
       /\
      /E2E\         10% - Critical flows only
     /------\
    /  Integ \      30% - API, DB, multi-layer
   /----------\
  /    Unit    \    60% - Business logic, edge cases
 /--------------\
```

### Quick reference

| Task | Tool | Command |
|------|------|---------|
| Run unit tests | Maven | `mvn test` |
| Run integration tests | Maven | `mvn verify` |
| Check coverage | JaCoCo | `mvn jacoco:check` |
| View coverage report | JaCoCo | `open target/site/jacoco/index.html` |
| Run specific test | Maven | `mvn test -Dtest=DoctorServiceTest` |
| Run tests in IDE | IntelliJ | `Ctrl+Shift+F10` |
| Debug test | IntelliJ | `Ctrl+Shift+F9` |

### Anti-patterns checklist
- [ ] ❌ Skip tests trong CI
- [ ] ❌ Test chỉ happy path
- [ ] ❌ Mock everything
- [ ] ❌ Test implementation details
- [ ] ❌ Duplicate test data setup
- [ ] ❌ Empty tests (no assertions)
- [ ] ❌ Flaky tests (random failures)
- [ ] ❌ Slow tests (> 1s/unit test)
- [ ] ❌ Tests phụ thuộc thứ tự
- [ ] ❌ Hardcoded test data
