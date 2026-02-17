# Domain 17: WebSocket & Real-time
> **Số practices:** 7 | 🔴 2 | 🟠 4 | 🟡 1
> **Trọng số:** ×1

---

## 17.01 | STOMP over WebSocket với Spring Messaging | 🟠 KHUYẾN NGHỊ

### Metadata
- **ID:** `WS-001`
- **Mức độ:** 🟠 KHUYẾN NGHỊ
- **Lý do:** Protocol chuẩn, dễ subscribe/unsubscribe, tích hợp Spring Security

### Tại sao?
- **Raw WebSocket** phức tạp khi implement routing, subscription, authentication
- **STOMP** (Simple Text Oriented Messaging Protocol) cung cấp frame-based protocol với command như CONNECT, SUBSCRIBE, SEND, DISCONNECT
- Spring Messaging + STOMP cho phép sử dụng annotation-based routing giống REST controller
- Hỗ trợ đầy đủ message broker (in-memory, RabbitMQ, ActiveMQ)
- Tích hợp tốt với Spring Security cho authentication/authorization

### ✅ Cách đúng

```java
// 1. Configuration - WebSocketConfig.java
@Configuration
@EnableWebSocketMessageBroker
public class WebSocketConfig implements WebSocketMessageBrokerConfigurer {

  @Override
  public void configureMessageBroker(MessageBrokerRegistry config) {
    // Prefix cho client subscribe: /topic, /queue
    config.enableSimpleBroker("/topic", "/queue");

    // Prefix cho client gửi message đến @MessageMapping
    config.setApplicationDestinationPrefixes("/app");

    // Prefix cho user-specific destination
    config.setUserDestinationPrefix("/user");
  }

  @Override
  public void registerStompEndpoints(StompEndpointRegistry registry) {
    registry.addEndpoint("/ws")
      .setAllowedOriginPatterns("*")
      .withSockJS(); // Fallback cho browser không hỗ trợ WebSocket
  }
}

// 2. Controller - NotificationController.java
@Controller
public class NotificationController {

  private final SimpMessagingTemplate messagingTemplate;

  public NotificationController(SimpMessagingTemplate messagingTemplate) {
    this.messagingTemplate = messagingTemplate;
  }

  // Client gửi message đến /app/send
  @MessageMapping("/send")
  @SendTo("/topic/messages")
  public MessageDto sendMessage(MessageDto message) {
    return new MessageDto(
      message.content(),
      LocalDateTime.now()
    );
  }

  // Client subscribe /topic/notifications
  @MessageMapping("/subscribe")
  public void subscribeNotifications() {
    // Logic xử lý subscription
  }

  // Gửi message đến user cụ thể
  public void sendToUser(String username, NotificationDto notification) {
    messagingTemplate.convertAndSendToUser(
      username,
      "/queue/notifications",
      notification
    );
  }

  // Broadcast đến tất cả subscribers
  public void broadcast(String destination, Object payload) {
    messagingTemplate.convertAndSend(destination, payload);
  }
}

// 3. DTO
public record MessageDto(
  String content,
  LocalDateTime timestamp
) {}

public record NotificationDto(
  String type,
  String message,
  LocalDateTime createdAt
) {}

// 4. Frontend - JavaScript client
const socket = new SockJS('/ws');
const stompClient = Stomp.over(socket);

stompClient.connect({}, function(frame) {
  console.log('Connected: ' + frame);

  // Subscribe topic chung
  stompClient.subscribe('/topic/messages', function(message) {
    const msg = JSON.parse(message.body);
    console.log('Received:', msg);
  });

  // Subscribe queue cá nhân
  stompClient.subscribe('/user/queue/notifications', function(notification) {
    const notif = JSON.parse(notification.body);
    console.log('Personal notification:', notif);
  });
});

// Gửi message
function sendMessage(content) {
  stompClient.send('/app/send', {}, JSON.stringify({
    content: content,
    timestamp: new Date().toISOString()
  }));
}
```

### ❌ Cách sai

```java
// ❌ Raw WebSocket handler - phức tạp, khó maintain
@Component
public class RawWebSocketHandler extends TextWebSocketHandler {

  private final Set<WebSocketSession> sessions = new CopyOnWriteArraySet<>();

  @Override
  public void afterConnectionEstablished(WebSocketSession session) {
    sessions.add(session);
  }

  @Override
  protected void handleTextMessage(WebSocketSession session, TextMessage message)
      throws Exception {
    // Phải tự parse JSON, routing, authentication
    String payload = message.getPayload();
    JSONObject json = new JSONObject(payload);

    String action = json.getString("action");
    if ("subscribe".equals(action)) {
      // Phải tự quản lý subscription
    } else if ("send".equals(action)) {
      // Phải tự broadcast
      for (WebSocketSession s : sessions) {
        if (s.isOpen()) {
          s.sendMessage(new TextMessage(payload));
        }
      }
    }
  }

  @Override
  public void afterConnectionClosed(WebSocketSession session, CloseStatus status) {
    sessions.remove(session);
  }
}

// ❌ Configuration cho raw WebSocket
@Configuration
@EnableWebSocket
public class RawWebSocketConfig implements WebSocketConfigurer {

  @Autowired
  private RawWebSocketHandler handler;

  @Override
  public void registerWebSocketHandlers(WebSocketHandlerRegistry registry) {
    registry.addHandler(handler, "/raw-ws");
  }
}
```

### Phát hiện

```regex
# Detect raw WebSocket usage
(?:extends\s+TextWebSocketHandler|implements\s+WebSocketHandler)

# Prefer STOMP
@EnableWebSocketMessageBroker
```

### Checklist
- [ ] Sử dụng `@EnableWebSocketMessageBroker` thay vì `@EnableWebSocket`
- [ ] Configure message broker với `/topic` (broadcast) và `/queue` (point-to-point)
- [ ] Sử dụng `@MessageMapping` thay vì manual routing
- [ ] Enable SockJS fallback cho browser cũ
- [ ] Sử dụng `SimpMessagingTemplate` để gửi message programmatically

---

## 17.02 | Authentication trên WebSocket handshake | 🔴 BẮT BUỘC

### Metadata
- **ID:** `WS-002`
- **Mức độ:** 🔴 BẮT BUỘC
- **Lý do:** Security - ngăn unauthorized access, session hijacking

### Tại sao?
- **WebSocket connection** tồn tại lâu hơn HTTP request, cần verify identity ngay từ handshake
- Không có concept "HTTP header" sau khi connection established
- Attacker có thể subscribe vào sensitive topics nếu không authenticate
- Spring Security hỗ trợ authentication trên WebSocket handshake qua `ChannelInterceptor`

### ✅ Cách đúng

```java
// 1. WebSocket Security Config
@Configuration
public class WebSocketSecurityConfig {

  @Bean
  public AuthorizationManager<Message<?>> messageAuthorizationManager(
      MessageMatcherDelegatingAuthorizationManager.Builder messages) {

    messages
      // Allow CONNECT, SUBSCRIBE, DISCONNECT without auth
      .simpTypeMatchers(SimpMessageType.CONNECT, SimpMessageType.HEARTBEAT,
                        SimpMessageType.UNSUBSCRIBE, SimpMessageType.DISCONNECT)
        .permitAll()

      // Require authentication for SUBSCRIBE
      .simpSubscribeDestMatchers("/user/queue/**").authenticated()
      .simpSubscribeDestMatchers("/topic/**").authenticated()

      // Require specific role for admin topics
      .simpSubscribeDestMatchers("/topic/admin/**").hasRole("ADMIN")

      // Require authentication for sending messages
      .simpDestMatchers("/app/**").authenticated()

      .anyMessage().denyAll();

    return messages.build();
  }
}

// 2. Handshake Interceptor - verify token
@Component
public class AuthHandshakeInterceptor implements HandshakeInterceptor {

  private final JwtTokenProvider tokenProvider;

  public AuthHandshakeInterceptor(JwtTokenProvider tokenProvider) {
    this.tokenProvider = tokenProvider;
  }

  @Override
  public boolean beforeHandshake(
      ServerHttpRequest request,
      ServerHttpResponse response,
      WebSocketHandler wsHandler,
      Map<String, Object> attributes) throws Exception {

    if (request instanceof ServletServerHttpRequest servletRequest) {
      HttpServletRequest httpRequest = servletRequest.getServletRequest();

      // Lấy token từ query param (vì WebSocket không support header)
      String token = httpRequest.getParameter("token");

      if (token != null && tokenProvider.validateToken(token)) {
        String username = tokenProvider.getUsernameFromToken(token);
        attributes.put("username", username);
        attributes.put("authenticated", true);
        return true;
      }
    }

    return false; // Reject handshake
  }

  @Override
  public void afterHandshake(
      ServerHttpRequest request,
      ServerHttpResponse response,
      WebSocketHandler wsHandler,
      Exception exception) {
    // No-op
  }
}

// 3. WebSocket Config với interceptor
@Configuration
@EnableWebSocketMessageBroker
public class WebSocketConfig implements WebSocketMessageBrokerConfigurer {

  private final AuthHandshakeInterceptor authInterceptor;

  public WebSocketConfig(AuthHandshakeInterceptor authInterceptor) {
    this.authInterceptor = authInterceptor;
  }

  @Override
  public void registerStompEndpoints(StompEndpointRegistry registry) {
    registry.addEndpoint("/ws")
      .setAllowedOriginPatterns("*")
      .addInterceptors(authInterceptor) // Add auth interceptor
      .withSockJS();
  }

  @Override
  public void configureClientInboundChannel(ChannelRegistration registration) {
    registration.interceptors(new ChannelInterceptor() {
      @Override
      public Message<?> preSend(Message<?> message, MessageChannel channel) {
        StompHeaderAccessor accessor =
          MessageHeaderAccessor.getAccessor(message, StompHeaderAccessor.class);

        if (StompCommand.CONNECT.equals(accessor.getCommand())) {
          // Set user principal từ session attributes
          Map<String, Object> sessionAttributes = accessor.getSessionAttributes();
          if (sessionAttributes != null) {
            String username = (String) sessionAttributes.get("username");
            if (username != null) {
              accessor.setUser(new UsernamePasswordAuthenticationToken(
                username, null, List.of(new SimpleGrantedAuthority("ROLE_USER"))
              ));
            }
          }
        }

        return message;
      }
    });
  }
}

// 4. Frontend - gửi token qua query param
function connectWebSocket(jwtToken) {
  const socket = new SockJS('/ws?token=' + jwtToken);
  const stompClient = Stomp.over(socket);

  stompClient.connect({}, function(frame) {
    console.log('Authenticated and connected');
  }, function(error) {
    console.error('Authentication failed:', error);
  });

  return stompClient;
}
```

### ❌ Cách sai

```java
// ❌ Không authenticate handshake
@Configuration
@EnableWebSocketMessageBroker
public class InsecureWebSocketConfig implements WebSocketMessageBrokerConfigurer {

  @Override
  public void registerStompEndpoints(StompEndpointRegistry registry) {
    registry.addEndpoint("/ws")
      .setAllowedOriginPatterns("*") // Ai cũng connect được!
      .withSockJS();
  }

  // ❌ Không check permission trước khi subscribe
  @Override
  public void configureMessageBroker(MessageBrokerRegistry config) {
    config.enableSimpleBroker("/topic", "/queue");
    config.setApplicationDestinationPrefixes("/app");
  }
}

// ❌ Controller không check authorization
@Controller
public class InsecureNotificationController {

  @MessageMapping("/admin/broadcast")
  @SendTo("/topic/admin/notifications")
  public NotificationDto adminBroadcast(NotificationDto notification) {
    // Ai cũng gửi được admin notification!
    return notification;
  }
}
```

### Phát hiện

```regex
# Detect missing auth interceptor
registerStompEndpoints\([^)]+\)(?![\s\S]{0,200}\.addInterceptors)

# Detect permitAll() without authentication
\.permitAll\(\)
```

### Checklist
- [ ] Implement `HandshakeInterceptor` để verify token/session
- [ ] Configure `AuthorizationManager<Message<?>>` cho message-level security
- [ ] Sử dụng `ChannelInterceptor` để set user principal
- [ ] Gửi token qua query param (vì WebSocket không hỗ trợ custom header)
- [ ] Reject handshake nếu authentication failed
- [ ] Check role/permission cho sensitive destinations

---

## 17.03 | Heartbeat/ping-pong cho connection health | 🟠 KHUYẾN NGHỊ

### Metadata
- **ID:** `WS-003`
- **Mức độ:** 🟠 KHUYẾN NGHỊ
- **Lý do:** Detect dead connections, tránh resource leak

### Tại sao?
- **Half-open connections** (client đã disconnect nhưng server không biết) tốn memory
- Network issue có thể làm connection "zombie" mà không trigger `onClose`
- Heartbeat giúp detect và cleanup dead connections sớm
- STOMP protocol hỗ trợ heartbeat natively

### ✅ Cách đúng

```java
// 1. Configure heartbeat trong WebSocketConfig
@Configuration
@EnableWebSocketMessageBroker
public class WebSocketConfig implements WebSocketMessageBrokerConfigurer {

  @Override
  public void configureMessageBroker(MessageBrokerRegistry config) {
    config.enableSimpleBroker("/topic", "/queue")
      .setHeartbeatValue(new long[]{10000, 10000}); // [outgoing, incoming] in ms
      // Server gửi heartbeat mỗi 10s, expect client heartbeat mỗi 10s

    config.setApplicationDestinationPrefixes("/app");
  }

  @Override
  public void registerStompEndpoints(StompEndpointRegistry registry) {
    registry.addEndpoint("/ws")
      .setAllowedOriginPatterns("*")
      .withSockJS()
      .setHeartbeatTime(25000); // SockJS heartbeat interval (ms)
  }
}

// 2. Session Event Listener - cleanup on disconnect
@Component
public class WebSocketEventListener {

  private static final Logger log = LoggerFactory.getLogger(WebSocketEventListener.class);

  @EventListener
  public void handleSessionConnected(SessionConnectedEvent event) {
    StompHeaderAccessor headers = StompHeaderAccessor.wrap(event.getMessage());
    String sessionId = headers.getSessionId();
    Principal user = headers.getUser();

    log.info("WebSocket connected: sessionId={}, user={}", sessionId,
             user != null ? user.getName() : "anonymous");
  }

  @EventListener
  public void handleSessionDisconnect(SessionDisconnectEvent event) {
    StompHeaderAccessor headers = StompHeaderAccessor.wrap(event.getMessage());
    String sessionId = headers.getSessionId();
    Principal user = headers.getUser();

    log.info("WebSocket disconnected: sessionId={}, user={}", sessionId,
             user != null ? user.getName() : "anonymous");

    // Cleanup resources
    cleanupSession(sessionId);
  }

  private void cleanupSession(String sessionId) {
    // Remove from active sessions map
    // Cancel pending tasks
    // Release resources
  }
}

// 3. Active Session Manager
@Component
public class ActiveSessionManager {

  private final Map<String, SessionInfo> activeSessions = new ConcurrentHashMap<>();
  private final SimpMessagingTemplate messagingTemplate;

  public ActiveSessionManager(SimpMessagingTemplate messagingTemplate) {
    this.messagingTemplate = messagingTemplate;
  }

  public void addSession(String sessionId, String username) {
    activeSessions.put(sessionId, new SessionInfo(username, Instant.now()));
  }

  public void removeSession(String sessionId) {
    activeSessions.remove(sessionId);
  }

  public void updateLastActivity(String sessionId) {
    SessionInfo info = activeSessions.get(sessionId);
    if (info != null) {
      info.updateLastActivity();
    }
  }

  // Scheduled task cleanup stale sessions
  @Scheduled(fixedRate = 60000) // Every 1 minute
  public void cleanupStaleSessions() {
    Instant threshold = Instant.now().minus(Duration.ofMinutes(5));

    activeSessions.entrySet().removeIf(entry -> {
      if (entry.getValue().lastActivity().isBefore(threshold)) {
        log.warn("Removing stale session: {}", entry.getKey());
        return true;
      }
      return false;
    });
  }

  public record SessionInfo(
    String username,
    Instant lastActivity
  ) {
    public void updateLastActivity() {
      // Immutable, cần tạo instance mới nếu muốn update
    }
  }
}

// 4. Frontend - handle heartbeat
const stompClient = Stomp.over(socket);

stompClient.heartbeat.outgoing = 10000; // Send heartbeat every 10s
stompClient.heartbeat.incoming = 10000; // Expect heartbeat every 10s

stompClient.connect({}, function(frame) {
  console.log('Connected with heartbeat enabled');
}, function(error) {
  console.error('Connection error:', error);
});

// Detect disconnect and reconnect
socket.onclose = function() {
  console.log('Connection closed, attempting to reconnect...');
  setTimeout(reconnect, 3000);
};

function reconnect() {
  // Implement reconnection logic
}
```

### ❌ Cách sai

```java
// ❌ Không configure heartbeat
@Configuration
@EnableWebSocketMessageBroker
public class NoHeartbeatConfig implements WebSocketMessageBrokerConfigurer {

  @Override
  public void configureMessageBroker(MessageBrokerRegistry config) {
    config.enableSimpleBroker("/topic", "/queue");
    // Không set heartbeat - connection có thể zombie
  }
}

// ❌ Không cleanup session on disconnect
@Component
public class NoCleanupListener {

  private final Map<String, Object> sessions = new HashMap<>();

  @EventListener
  public void handleSessionConnected(SessionConnectedEvent event) {
    String sessionId = extractSessionId(event);
    sessions.put(sessionId, new Object()); // Add to map
  }

  // ❌ Không có @EventListener cho SessionDisconnectEvent
  // sessions map sẽ leak memory!
}
```

### Phát hiện

```regex
# Detect missing heartbeat configuration
enableSimpleBroker\([^)]+\)(?![\s\S]{0,100}\.setHeartbeatValue)

# Detect missing disconnect listener
@EventListener[\s\S]{0,50}SessionConnectedEvent(?![\s\S]{0,500}SessionDisconnectEvent)
```

### Checklist
- [ ] Configure heartbeat interval cho STOMP broker (`setHeartbeatValue`)
- [ ] Configure heartbeat cho SockJS fallback (`setHeartbeatTime`)
- [ ] Implement `@EventListener` cho `SessionDisconnectEvent`
- [ ] Cleanup resources (maps, tasks) khi session disconnect
- [ ] Scheduled task để cleanup stale sessions
- [ ] Frontend handle reconnection khi connection lost

---

## 17.04 | Message size limit để tránh memory abuse | 🔴 BẮT BUỘC

### Metadata
- **ID:** `WS-004`
- **Mức độ:** 🔴 BẮT BUỘC
- **Lý do:** Security - ngăn DoS attack, memory exhaustion

### Tại sao?
- **Attacker** có thể gửi message cực lớn (vài MB/GB) để crash server
- **WebSocket** không có built-in size limit như HTTP (nginx/tomcat limit)
- Memory leak nếu buffer message quá lớn
- Impact toàn bộ users khác khi server OOM

### ✅ Cách đúng

```java
// 1. WebSocket Transport Config
@Configuration
@EnableWebSocketMessageBroker
public class WebSocketConfig implements WebSocketMessageBrokerConfigurer {

  @Override
  public void configureWebSocketTransport(WebSocketTransportRegistration registration) {
    registration
      .setMessageSizeLimit(128 * 1024)        // 128 KB per message
      .setSendBufferSizeLimit(512 * 1024)     // 512 KB send buffer
      .setSendTimeLimit(20 * 1000)            // 20 seconds timeout
      .setTimeToFirstMessage(30 * 1000);      // 30 seconds to first message
  }

  @Override
  public void configureMessageBroker(MessageBrokerRegistry config) {
    config.enableSimpleBroker("/topic", "/queue");
    config.setApplicationDestinationPrefixes("/app");
  }
}

// 2. Message Size Validator
@Component
public class MessageSizeInterceptor implements ChannelInterceptor {

  private static final Logger log = LoggerFactory.getLogger(MessageSizeInterceptor.class);
  private static final int MAX_MESSAGE_SIZE = 128 * 1024; // 128 KB

  @Override
  public Message<?> preSend(Message<?> message, MessageChannel channel) {
    StompHeaderAccessor accessor =
      MessageHeaderAccessor.getAccessor(message, StompHeaderAccessor.class);

    if (accessor != null && StompCommand.SEND.equals(accessor.getCommand())) {
      byte[] payload = (byte[]) message.getPayload();

      if (payload.length > MAX_MESSAGE_SIZE) {
        String sessionId = accessor.getSessionId();
        log.warn("Message size exceeded limit: sessionId={}, size={} bytes",
                 sessionId, payload.length);

        // Reject message
        throw new MessageSizeException(
          "Message size " + payload.length + " bytes exceeds limit " + MAX_MESSAGE_SIZE
        );
      }
    }

    return message;
  }
}

// 3. Custom Exception
public class MessageSizeException extends RuntimeException {
  public MessageSizeException(String message) {
    super(message);
  }
}

// 4. Exception Handler cho WebSocket
@ControllerAdvice
public class WebSocketExceptionHandler {

  private static final Logger log = LoggerFactory.getLogger(WebSocketExceptionHandler.class);

  @MessageExceptionHandler(MessageSizeException.class)
  @SendToUser("/queue/errors")
  public ErrorDto handleMessageSizeException(MessageSizeException ex) {
    log.error("Message size error: {}", ex.getMessage());
    return new ErrorDto("MESSAGE_TOO_LARGE", ex.getMessage());
  }

  @MessageExceptionHandler(Exception.class)
  @SendToUser("/queue/errors")
  public ErrorDto handleGenericException(Exception ex) {
    log.error("WebSocket error", ex);
    return new ErrorDto("INTERNAL_ERROR", "An error occurred processing your message");
  }

  public record ErrorDto(String code, String message) {}
}

// 5. Rate Limiting per Session
@Component
public class RateLimitInterceptor implements ChannelInterceptor {

  private static final int MAX_MESSAGES_PER_MINUTE = 60;
  private final Map<String, RateLimiter> limiters = new ConcurrentHashMap<>();

  @Override
  public Message<?> preSend(Message<?> message, MessageChannel channel) {
    StompHeaderAccessor accessor =
      MessageHeaderAccessor.getAccessor(message, StompHeaderAccessor.class);

    if (accessor != null && StompCommand.SEND.equals(accessor.getCommand())) {
      String sessionId = accessor.getSessionId();
      RateLimiter limiter = limiters.computeIfAbsent(
        sessionId,
        k -> RateLimiter.create(MAX_MESSAGES_PER_MINUTE / 60.0) // 1 msg/sec avg
      );

      if (!limiter.tryAcquire()) {
        throw new RateLimitException("Too many messages, please slow down");
      }
    }

    return message;
  }

  @EventListener
  public void handleSessionDisconnect(SessionDisconnectEvent event) {
    StompHeaderAccessor headers = StompHeaderAccessor.wrap(event.getMessage());
    limiters.remove(headers.getSessionId());
  }
}

// 6. Frontend - validate before send
function sendMessage(content) {
  const payload = JSON.stringify({ content: content });
  const sizeInBytes = new Blob([payload]).size;

  if (sizeInBytes > 128 * 1024) {
    console.error('Message too large:', sizeInBytes, 'bytes');
    alert('Message exceeds 128 KB limit');
    return;
  }

  stompClient.send('/app/send', {}, payload);
}

// Subscribe error queue
stompClient.subscribe('/user/queue/errors', function(message) {
  const error = JSON.parse(message.body);
  console.error('Server error:', error.code, error.message);

  if (error.code === 'MESSAGE_TOO_LARGE') {
    alert('Your message is too large. Please reduce the size.');
  }
});
```

### ❌ Cách sai

```java
// ❌ Không configure message size limit
@Configuration
@EnableWebSocketMessageBroker
public class UnsafeWebSocketConfig implements WebSocketMessageBrokerConfigurer {

  @Override
  public void configureMessageBroker(MessageBrokerRegistry config) {
    config.enableSimpleBroker("/topic", "/queue");
    config.setApplicationDestinationPrefixes("/app");
  }

  // ❌ Không override configureWebSocketTransport
  // Default limit rất lớn, có thể bị abuse!
}

// ❌ Controller không validate payload size
@Controller
public class UnsafeController {

  @MessageMapping("/upload")
  @SendTo("/topic/uploads")
  public UploadDto handleUpload(UploadDto upload) {
    // Nhận payload bao nhiêu MB cũng được!
    // Buffer hết vào memory → OOM
    byte[] data = upload.data();
    // Process...
    return upload;
  }

  public record UploadDto(String filename, byte[] data) {}
}
```

### Phát hiện

```regex
# Detect missing transport configuration
@EnableWebSocketMessageBroker(?![\s\S]{0,1000}configureWebSocketTransport)

# Detect missing size limit
configureWebSocketTransport\([^)]+\)(?![\s\S]{0,200}setMessageSizeLimit)
```

### Checklist
- [ ] Configure `setMessageSizeLimit` trong `configureWebSocketTransport` (khuyến nghị 128 KB - 1 MB)
- [ ] Configure `setSendBufferSizeLimit` và `setSendTimeLimit`
- [ ] Implement `ChannelInterceptor` để validate message size
- [ ] Implement rate limiting per session
- [ ] Exception handler trả error message về client
- [ ] Frontend validate size trước khi gửi

---

## 17.05 | Reconnection strategy phía client | 🟡 NÊN CÓ

### Metadata
- **ID:** `WS-005`
- **Mức độ:** 🟡 NÊN CÓ
- **Lý do:** UX - tránh user phải reload page khi network issue

### Tại sao?
- **Network instability** (mobile, WiFi switching) gây disconnect tạm thời
- Server restart/deploy làm disconnect toàn bộ clients
- Exponential backoff tránh thundering herd khi server khởi động lại
- Re-subscribe vào topics sau khi reconnect

### ✅ Cách đúng

```java
// 1. Backend - Connection Event Tracker
@Component
public class ConnectionEventTracker {

  private static final Logger log = LoggerFactory.getLogger(ConnectionEventTracker.class);
  private final SimpMessagingTemplate messagingTemplate;

  public ConnectionEventTracker(SimpMessagingTemplate messagingTemplate) {
    this.messagingTemplate = messagingTemplate;
  }

  @EventListener
  public void handleSessionConnected(SessionConnectedEvent event) {
    StompHeaderAccessor headers = StompHeaderAccessor.wrap(event.getMessage());
    String sessionId = headers.getSessionId();
    Principal user = headers.getUser();

    log.info("Client connected: sessionId={}, user={}", sessionId,
             user != null ? user.getName() : "anonymous");
  }

  @EventListener
  public void handleSessionDisconnect(SessionDisconnectEvent event) {
    StompHeaderAccessor headers = StompHeaderAccessor.wrap(event.getMessage());
    String sessionId = headers.getSessionId();

    log.info("Client disconnected: sessionId={}", sessionId);
  }
}

// 2. Backend - Server Health Endpoint
@RestController
@RequestMapping("/api/health")
public class HealthController {

  @GetMapping("/websocket")
  public ResponseEntity<Map<String, Object>> websocketHealth() {
    return ResponseEntity.ok(Map.of(
      "status", "UP",
      "timestamp", System.currentTimeMillis()
    ));
  }
}
```

```javascript
// 3. Frontend - Reconnection Manager (JavaScript/TypeScript)
class WebSocketReconnectionManager {
  constructor(url, token, options = {}) {
    this.url = url;
    this.token = token;
    this.maxRetries = options.maxRetries || 10;
    this.initialDelay = options.initialDelay || 1000; // 1 second
    this.maxDelay = options.maxDelay || 30000; // 30 seconds
    this.backoffMultiplier = options.backoffMultiplier || 1.5;

    this.retryCount = 0;
    this.currentDelay = this.initialDelay;
    this.stompClient = null;
    this.subscriptions = new Map(); // Store subscriptions for re-subscribe
    this.isConnected = false;
    this.reconnectTimer = null;
  }

  connect() {
    console.log(`Connecting to ${this.url}...`);

    const socket = new SockJS(`${this.url}?token=${this.token}`);
    this.stompClient = Stomp.over(socket);

    // Disable debug logging in production
    this.stompClient.debug = (msg) => {
      if (process.env.NODE_ENV === 'development') {
        console.log(msg);
      }
    };

    this.stompClient.connect(
      {},
      (frame) => this.onConnected(frame),
      (error) => this.onError(error)
    );

    // Handle disconnect
    socket.onclose = () => {
      console.log('WebSocket connection closed');
      this.isConnected = false;
      this.scheduleReconnect();
    };
  }

  onConnected(frame) {
    console.log('WebSocket connected:', frame);
    this.isConnected = true;
    this.retryCount = 0;
    this.currentDelay = this.initialDelay;

    // Re-subscribe to all previous subscriptions
    this.resubscribe();

    // Notify application
    if (this.options.onConnected) {
      this.options.onConnected(frame);
    }
  }

  onError(error) {
    console.error('WebSocket connection error:', error);
    this.isConnected = false;
    this.scheduleReconnect();

    // Notify application
    if (this.options.onError) {
      this.options.onError(error);
    }
  }

  scheduleReconnect() {
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
    }

    if (this.retryCount >= this.maxRetries) {
      console.error(`Max reconnection attempts (${this.maxRetries}) reached`);
      if (this.options.onMaxRetriesReached) {
        this.options.onMaxRetriesReached();
      }
      return;
    }

    this.retryCount++;
    console.log(
      `Scheduling reconnect attempt ${this.retryCount}/${this.maxRetries} ` +
      `in ${this.currentDelay}ms...`
    );

    this.reconnectTimer = setTimeout(() => {
      this.connect();
    }, this.currentDelay);

    // Exponential backoff with jitter
    this.currentDelay = Math.min(
      this.currentDelay * this.backoffMultiplier + Math.random() * 1000,
      this.maxDelay
    );
  }

  subscribe(destination, callback) {
    if (!this.isConnected) {
      console.warn('Not connected, subscription will be deferred');
    }

    // Store subscription for re-subscribe
    this.subscriptions.set(destination, callback);

    // Subscribe if connected
    if (this.isConnected && this.stompClient) {
      return this.stompClient.subscribe(destination, callback);
    }

    return null;
  }

  resubscribe() {
    console.log(`Re-subscribing to ${this.subscriptions.size} destinations...`);

    this.subscriptions.forEach((callback, destination) => {
      console.log(`Re-subscribing to ${destination}`);
      this.stompClient.subscribe(destination, callback);
    });
  }

  send(destination, headers, body) {
    if (!this.isConnected) {
      throw new Error('Cannot send message: WebSocket not connected');
    }

    this.stompClient.send(destination, headers, body);
  }

  disconnect() {
    console.log('Disconnecting WebSocket...');

    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }

    if (this.stompClient && this.isConnected) {
      this.stompClient.disconnect(() => {
        console.log('WebSocket disconnected');
      });
    }

    this.subscriptions.clear();
    this.isConnected = false;
  }

  isConnectedNow() {
    return this.isConnected;
  }
}

// 4. Usage Example
const wsManager = new WebSocketReconnectionManager('/ws', jwtToken, {
  maxRetries: 10,
  initialDelay: 1000,
  maxDelay: 30000,
  backoffMultiplier: 1.5,

  onConnected: (frame) => {
    console.log('Application: Connected to WebSocket');
    updateUIConnectionStatus('connected');
  },

  onError: (error) => {
    console.error('Application: WebSocket error', error);
    updateUIConnectionStatus('error');
  },

  onMaxRetriesReached: () => {
    console.error('Application: Cannot reconnect, please refresh page');
    showReconnectButton();
  }
});

// Connect
wsManager.connect();

// Subscribe (auto re-subscribe on reconnect)
wsManager.subscribe('/topic/notifications', (message) => {
  const notification = JSON.parse(message.body);
  displayNotification(notification);
});

wsManager.subscribe('/user/queue/personal', (message) => {
  const data = JSON.parse(message.body);
  handlePersonalMessage(data);
});

// Send message
function sendChatMessage(content) {
  try {
    wsManager.send('/app/chat', {}, JSON.stringify({ content }));
  } catch (error) {
    console.error('Failed to send message:', error);
    alert('Not connected to server. Please wait...');
  }
}

// UI helpers
function updateUIConnectionStatus(status) {
  const indicator = document.getElementById('connection-status');
  indicator.className = `status-${status}`;
  indicator.textContent = status === 'connected' ? 'Online' : 'Offline';
}

function showReconnectButton() {
  const btn = document.getElementById('reconnect-btn');
  btn.style.display = 'block';
  btn.onclick = () => {
    wsManager.retryCount = 0;
    wsManager.currentDelay = wsManager.initialDelay;
    wsManager.connect();
  };
}
```

### ❌ Cách sai

```javascript
// ❌ Không có reconnection logic
const socket = new SockJS('/ws?token=' + jwtToken);
const stompClient = Stomp.over(socket);

stompClient.connect({}, function(frame) {
  console.log('Connected');

  stompClient.subscribe('/topic/notifications', function(message) {
    displayNotification(JSON.parse(message.body));
  });
});

// ❌ Khi disconnect, user phải reload page!
// Không có onclose handler, không có retry logic

// ❌ Immediate retry (thundering herd)
socket.onclose = function() {
  setTimeout(() => {
    stompClient.connect({}); // Retry ngay sau 1s, không có backoff
  }, 1000);
};

// ❌ Không re-subscribe sau reconnect
socket.onclose = function() {
  // Subscriptions bị mất!
};
```

### Phát hiện

```regex
# Detect missing onclose handler
new SockJS\([^)]+\)(?![\s\S]{0,500}\.onclose)

# Detect missing exponential backoff
setTimeout\([^)]+connect[^)]*\)(?![\s\S]{0,200}backoff|delay.*\*)
```

### Checklist
- [ ] Implement exponential backoff với jitter
- [ ] Max retry limit để tránh infinite loop
- [ ] Store subscriptions để re-subscribe sau reconnect
- [ ] UI indicator cho connection status (online/offline)
- [ ] Manual reconnect button khi max retries reached
- [ ] Clear timers khi disconnect manually

---

## 17.06 | Broadcast throttling tránh message flood | 🟠 KHUYẾN NGHỊ

### Metadata
- **ID:** `WS-006`
- **Mức độ:** 🟠 KHUYẾN NGHỊ
- **Lý do:** Performance - tránh overwhelm clients với too many messages

### Tại sao?
- **High-frequency events** (stock price, game state) có thể gửi hàng trăm messages/second
- Client browser không kịp render → UI lag, battery drain
- Network congestion nếu broadcast quá nhiều
- Throttling/debouncing giúp giảm message rate nhưng vẫn giữ được real-time experience

### ✅ Cách đúng

```java
// 1. Throttled Broadcaster Service
@Service
public class ThrottledBroadcaster {

  private static final Logger log = LoggerFactory.getLogger(ThrottledBroadcaster.class);
  private final SimpMessagingTemplate messagingTemplate;
  private final Map<String, ScheduledFuture<?>> scheduledBroadcasts = new ConcurrentHashMap<>();
  private final ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(4);

  public ThrottledBroadcaster(SimpMessagingTemplate messagingTemplate) {
    this.messagingTemplate = messagingTemplate;
  }

  /**
   * Throttle broadcast: gửi tối đa 1 message per interval
   * Chỉ gửi message cuối cùng trong window
   */
  public void throttleBroadcast(String destination, Object payload, Duration interval) {
    String key = destination;

    // Cancel previous scheduled broadcast
    ScheduledFuture<?> previousTask = scheduledBroadcasts.get(key);
    if (previousTask != null && !previousTask.isDone()) {
      previousTask.cancel(false);
    }

    // Schedule new broadcast
    ScheduledFuture<?> task = scheduler.schedule(
      () -> {
        messagingTemplate.convertAndSend(destination, payload);
        scheduledBroadcasts.remove(key);
        log.debug("Throttled broadcast sent to {}", destination);
      },
      interval.toMillis(),
      TimeUnit.MILLISECONDS
    );

    scheduledBroadcasts.put(key, task);
  }

  /**
   * Debounce broadcast: chỉ gửi sau khi không có update trong duration
   */
  public void debounceBroadcast(String destination, Object payload, Duration debounceTime) {
    throttleBroadcast(destination, payload, debounceTime);
  }

  @PreDestroy
  public void shutdown() {
    scheduler.shutdown();
    try {
      if (!scheduler.awaitTermination(5, TimeUnit.SECONDS)) {
        scheduler.shutdownNow();
      }
    } catch (InterruptedException e) {
      scheduler.shutdownNow();
      Thread.currentThread().interrupt();
    }
  }
}

// 2. Rate-Limited Topic Broadcaster
@Service
public class RateLimitedBroadcaster {

  private static final Logger log = LoggerFactory.getLogger(RateLimitedBroadcaster.class);
  private final SimpMessagingTemplate messagingTemplate;
  private final Map<String, RateLimiter> rateLimiters = new ConcurrentHashMap<>();

  public RateLimitedBroadcaster(SimpMessagingTemplate messagingTemplate) {
    this.messagingTemplate = messagingTemplate;
  }

  /**
   * Broadcast với rate limit (permits per second)
   */
  public boolean tryBroadcast(String destination, Object payload, double permitsPerSecond) {
    RateLimiter limiter = rateLimiters.computeIfAbsent(
      destination,
      k -> RateLimiter.create(permitsPerSecond)
    );

    if (limiter.tryAcquire()) {
      messagingTemplate.convertAndSend(destination, payload);
      return true;
    } else {
      log.debug("Broadcast to {} rate limited, dropped message", destination);
      return false;
    }
  }

  /**
   * Broadcast blocking (chờ đến khi có permit)
   */
  public void broadcast(String destination, Object payload, double permitsPerSecond) {
    RateLimiter limiter = rateLimiters.computeIfAbsent(
      destination,
      k -> RateLimiter.create(permitsPerSecond)
    );

    limiter.acquire(); // Block until permit available
    messagingTemplate.convertAndSend(destination, payload);
  }
}

// 3. Example: Stock Price Broadcaster
@Service
public class StockPriceService {

  private final ThrottledBroadcaster throttledBroadcaster;
  private final RateLimitedBroadcaster rateLimitedBroadcaster;

  public StockPriceService(
      ThrottledBroadcaster throttledBroadcaster,
      RateLimitedBroadcaster rateLimitedBroadcaster) {
    this.throttledBroadcaster = throttledBroadcaster;
    this.rateLimitedBroadcaster = rateLimitedBroadcaster;
  }

  /**
   * Receive stock price update (có thể 100 updates/sec)
   * Throttle để chỉ gửi 1 update/100ms = 10 updates/sec
   */
  @EventListener
  public void handleStockPriceUpdate(StockPriceUpdateEvent event) {
    StockPriceDto dto = new StockPriceDto(
      event.symbol(),
      event.price(),
      event.timestamp()
    );

    // Throttle: gửi giá cuối cùng mỗi 100ms
    throttledBroadcaster.throttleBroadcast(
      "/topic/stock/" + event.symbol(),
      dto,
      Duration.ofMillis(100)
    );
  }

  /**
   * Alternative: Rate limit to 10 messages/sec, drop excess
   */
  public void broadcastStockPriceRateLimited(StockPriceDto dto) {
    boolean sent = rateLimitedBroadcaster.tryBroadcast(
      "/topic/stock/" + dto.symbol(),
      dto,
      10.0 // 10 messages per second max
    );

    if (!sent) {
      // Message dropped due to rate limit
      // Có thể log hoặc aggregate
    }
  }

  public record StockPriceDto(
    String symbol,
    BigDecimal price,
    Instant timestamp
  ) {}

  public record StockPriceUpdateEvent(
    String symbol,
    BigDecimal price,
    Instant timestamp
  ) {}
}

// 4. Example: Game State Broadcaster (60 FPS → 10 FPS)
@Service
public class GameStateService {

  private final ThrottledBroadcaster broadcaster;
  private final Map<String, GameState> latestStates = new ConcurrentHashMap<>();

  public GameStateService(ThrottledBroadcaster broadcaster) {
    this.broadcaster = broadcaster;
  }

  /**
   * Game loop update 60 times/sec
   * Broadcast chỉ 10 times/sec
   */
  public void updateGameState(String gameId, GameState state) {
    latestStates.put(gameId, state);

    // Throttle broadcast to 100ms = 10 FPS
    broadcaster.throttleBroadcast(
      "/topic/game/" + gameId + "/state",
      state,
      Duration.ofMillis(100)
    );
  }

  public record GameState(
    String gameId,
    List<PlayerPosition> players,
    long timestamp
  ) {}

  public record PlayerPosition(String playerId, int x, int y) {}
}
```

### ❌ Cách sai

```java
// ❌ Broadcast mọi event không throttle
@Service
public class UnthrottledStockService {

  private final SimpMessagingTemplate messagingTemplate;

  public UnthrottledStockService(SimpMessagingTemplate messagingTemplate) {
    this.messagingTemplate = messagingTemplate;
  }

  @EventListener
  public void handleStockPriceUpdate(StockPriceUpdateEvent event) {
    // Receive 100 events/sec → broadcast 100 messages/sec
    // Client không kịp xử lý, UI lag!
    messagingTemplate.convertAndSend(
      "/topic/stock/" + event.symbol(),
      new StockPriceDto(event.symbol(), event.price(), event.timestamp())
    );
  }
}

// ❌ Không có rate limit cho broadcast
@Controller
public class UncontrolledBroadcastController {

  private final SimpMessagingTemplate messagingTemplate;

  @Scheduled(fixedDelay = 10) // Mỗi 10ms = 100 FPS!
  public void broadcastGameState() {
    // Overwhelm clients với 100 messages/sec
    messagingTemplate.convertAndSend("/topic/game/state", computeState());
  }
}
```

### Phát hiện

```regex
# Detect high-frequency scheduled broadcast without throttling
@Scheduled\(fixedDelay\s*=\s*[1-9][0-9]?\)[\s\S]{0,200}convertAndSend

# Detect @EventListener broadcast without throttling
@EventListener[\s\S]{0,300}convertAndSend(?![\s\S]{0,200}throttle|rateLimiter)
```

### Checklist
- [ ] Implement throttling cho high-frequency events (stock, game state)
- [ ] Sử dụng `RateLimiter` (Guava) hoặc custom scheduler
- [ ] Debounce cho events cần settled value (search, input)
- [ ] Monitor broadcast rate qua metrics
- [ ] Frontend buffer/batch updates nếu cần
- [ ] Aggregate dropped messages nếu cần (trung bình, min/max)

---

## 17.07 | Session cleanup khi disconnect | 🟠 KHUYẾN NGHỊ

### Metadata
- **ID:** `WS-007`
- **Mức độ:** 🟠 KHUYẾN NGHỊ
- **Lý do:** Resource management - tránh memory leak

### Tại sao?
- **WebSocket sessions** có thể associate với resources (timers, subscriptions, cache)
- Không cleanup → memory leak, stale data
- `SessionDisconnectEvent` cung cấp hook để cleanup
- Cleanup cả subscription metadata, pending tasks, active session maps

### ✅ Cách đúng

```java
// 1. Session Registry
@Component
public class WebSocketSessionRegistry {

  private static final Logger log = LoggerFactory.getLogger(WebSocketSessionRegistry.class);

  // sessionId → SessionMetadata
  private final Map<String, SessionMetadata> sessions = new ConcurrentHashMap<>();

  // username → Set<sessionId> (một user có thể có nhiều tabs)
  private final Map<String, Set<String>> userSessions = new ConcurrentHashMap<>();

  public void registerSession(String sessionId, String username) {
    SessionMetadata metadata = new SessionMetadata(sessionId, username, Instant.now());
    sessions.put(sessionId, metadata);

    userSessions.computeIfAbsent(username, k -> ConcurrentHashMap.newKeySet())
      .add(sessionId);

    log.info("Session registered: sessionId={}, username={}, totalSessions={}",
             sessionId, username, sessions.size());
  }

  public void unregisterSession(String sessionId) {
    SessionMetadata metadata = sessions.remove(sessionId);

    if (metadata != null) {
      String username = metadata.username();
      Set<String> userSessionIds = userSessions.get(username);

      if (userSessionIds != null) {
        userSessionIds.remove(sessionId);

        // Nếu user không còn session nào, remove khỏi map
        if (userSessionIds.isEmpty()) {
          userSessions.remove(username);
          log.info("User {} fully disconnected", username);
        }
      }

      log.info("Session unregistered: sessionId={}, username={}, remainingSessions={}",
               sessionId, username, sessions.size());
    }
  }

  public boolean isUserOnline(String username) {
    Set<String> sessionIds = userSessions.get(username);
    return sessionIds != null && !sessionIds.isEmpty();
  }

  public Set<String> getActiveUsernames() {
    return new HashSet<>(userSessions.keySet());
  }

  public int getTotalSessions() {
    return sessions.size();
  }

  public Optional<SessionMetadata> getSessionMetadata(String sessionId) {
    return Optional.ofNullable(sessions.get(sessionId));
  }

  public record SessionMetadata(
    String sessionId,
    String username,
    Instant connectedAt
  ) {}
}

// 2. Session Resource Manager
@Component
public class SessionResourceManager {

  private static final Logger log = LoggerFactory.getLogger(SessionResourceManager.class);

  // sessionId → List<ScheduledFuture>
  private final Map<String, List<ScheduledFuture<?>>> sessionTasks = new ConcurrentHashMap<>();

  // sessionId → Set<String> (subscribed destinations)
  private final Map<String, Set<String>> sessionSubscriptions = new ConcurrentHashMap<>();

  public void addTask(String sessionId, ScheduledFuture<?> task) {
    sessionTasks.computeIfAbsent(sessionId, k -> new CopyOnWriteArrayList<>())
      .add(task);
  }

  public void addSubscription(String sessionId, String destination) {
    sessionSubscriptions.computeIfAbsent(sessionId, k -> ConcurrentHashMap.newKeySet())
      .add(destination);
  }

  public void cleanupSession(String sessionId) {
    // Cancel all scheduled tasks
    List<ScheduledFuture<?>> tasks = sessionTasks.remove(sessionId);
    if (tasks != null) {
      int cancelledCount = 0;
      for (ScheduledFuture<?> task : tasks) {
        if (!task.isDone()) {
          task.cancel(false);
          cancelledCount++;
        }
      }
      log.info("Cancelled {} tasks for session {}", cancelledCount, sessionId);
    }

    // Remove subscriptions
    Set<String> subscriptions = sessionSubscriptions.remove(sessionId);
    if (subscriptions != null) {
      log.info("Removed {} subscriptions for session {}", subscriptions.size(), sessionId);
    }
  }

  public Set<String> getSessionSubscriptions(String sessionId) {
    return sessionSubscriptions.getOrDefault(sessionId, Set.of());
  }
}

// 3. WebSocket Event Listener với Cleanup
@Component
public class WebSocketCleanupListener {

  private static final Logger log = LoggerFactory.getLogger(WebSocketCleanupListener.class);

  private final WebSocketSessionRegistry sessionRegistry;
  private final SessionResourceManager resourceManager;
  private final SimpMessagingTemplate messagingTemplate;

  public WebSocketCleanupListener(
      WebSocketSessionRegistry sessionRegistry,
      SessionResourceManager resourceManager,
      SimpMessagingTemplate messagingTemplate) {
    this.sessionRegistry = sessionRegistry;
    this.resourceManager = resourceManager;
    this.messagingTemplate = messagingTemplate;
  }

  @EventListener
  public void handleSessionConnected(SessionConnectedEvent event) {
    StompHeaderAccessor headers = StompHeaderAccessor.wrap(event.getMessage());
    String sessionId = headers.getSessionId();
    Principal user = headers.getUser();

    if (user != null) {
      String username = user.getName();
      sessionRegistry.registerSession(sessionId, username);

      // Broadcast user online status
      messagingTemplate.convertAndSend("/topic/users/online", Map.of(
        "username", username,
        "status", "ONLINE",
        "timestamp", Instant.now()
      ));
    }
  }

  @EventListener
  public void handleSessionDisconnect(SessionDisconnectEvent event) {
    StompHeaderAccessor headers = StompHeaderAccessor.wrap(event.getMessage());
    String sessionId = headers.getSessionId();
    Principal user = headers.getUser();

    // Cleanup resources
    resourceManager.cleanupSession(sessionId);

    // Unregister session
    if (user != null) {
      String username = user.getName();
      sessionRegistry.unregisterSession(sessionId);

      // Nếu user không còn session nào, broadcast offline status
      if (!sessionRegistry.isUserOnline(username)) {
        messagingTemplate.convertAndSend("/topic/users/online", Map.of(
          "username", username,
          "status", "OFFLINE",
          "timestamp", Instant.now()
        ));
      }
    }
  }

  @EventListener
  public void handleSubscribeEvent(SessionSubscribeEvent event) {
    StompHeaderAccessor headers = StompHeaderAccessor.wrap(event.getMessage());
    String sessionId = headers.getSessionId();
    String destination = headers.getDestination();

    if (destination != null) {
      resourceManager.addSubscription(sessionId, destination);
      log.debug("Session {} subscribed to {}", sessionId, destination);
    }
  }

  @EventListener
  public void handleUnsubscribeEvent(SessionUnsubscribeEvent event) {
    StompHeaderAccessor headers = StompHeaderAccessor.wrap(event.getMessage());
    String sessionId = headers.getSessionId();
    String subscriptionId = headers.getSubscriptionId();

    log.debug("Session {} unsubscribed: subscriptionId={}", sessionId, subscriptionId);
  }
}

// 4. Scheduled Cleanup cho Stale Sessions
@Component
public class StaleSessionCleaner {

  private static final Logger log = LoggerFactory.getLogger(StaleSessionCleaner.class);
  private final WebSocketSessionRegistry sessionRegistry;
  private final SessionResourceManager resourceManager;

  public StaleSessionCleaner(
      WebSocketSessionRegistry sessionRegistry,
      SessionResourceManager resourceManager) {
    this.sessionRegistry = sessionRegistry;
    this.resourceManager = resourceManager;
  }

  @Scheduled(fixedRate = 60000) // Every 1 minute
  public void cleanupStaleSessions() {
    Instant threshold = Instant.now().minus(Duration.ofMinutes(10));

    sessionRegistry.sessions.entrySet().removeIf(entry -> {
      String sessionId = entry.getKey();
      WebSocketSessionRegistry.SessionMetadata metadata = entry.getValue();

      if (metadata.connectedAt().isBefore(threshold)) {
        log.warn("Cleaning up stale session: sessionId={}, connectedAt={}",
                 sessionId, metadata.connectedAt());

        resourceManager.cleanupSession(sessionId);
        sessionRegistry.unregisterSession(sessionId);

        return true;
      }

      return false;
    });
  }
}

// 5. Metrics Monitoring
@Component
public class WebSocketMetrics {

  private final WebSocketSessionRegistry sessionRegistry;
  private final MeterRegistry meterRegistry;

  public WebSocketMetrics(
      WebSocketSessionRegistry sessionRegistry,
      MeterRegistry meterRegistry) {
    this.sessionRegistry = sessionRegistry;
    this.meterRegistry = meterRegistry;

    // Register gauge
    Gauge.builder("websocket.sessions.active", sessionRegistry,
                  WebSocketSessionRegistry::getTotalSessions)
      .description("Number of active WebSocket sessions")
      .register(meterRegistry);

    Gauge.builder("websocket.users.online",
                  sessionRegistry.getActiveUsernames(), Set::size)
      .description("Number of online users")
      .register(meterRegistry);
  }
}
```

### ❌ Cách sai

```java
// ❌ Không cleanup resources on disconnect
@Component
public class NoCleanupListener {

  private final Map<String, ScheduledFuture<?>> tasks = new HashMap<>();

  @EventListener
  public void handleSessionConnected(SessionConnectedEvent event) {
    String sessionId = extractSessionId(event);

    // Schedule task
    ScheduledFuture<?> task = schedulePeriodicTask(sessionId);
    tasks.put(sessionId, task);
  }

  // ❌ Không có listener cho SessionDisconnectEvent
  // tasks map sẽ leak memory, tasks continue chạy!
}

// ❌ Không track user online status
@Component
public class NoOnlineTrackingListener {

  @EventListener
  public void handleSessionConnected(SessionConnectedEvent event) {
    // Log connection nhưng không track state
    log.info("User connected");
  }

  @EventListener
  public void handleSessionDisconnect(SessionDisconnectEvent event) {
    // Log disconnect nhưng không cleanup
    log.info("User disconnected");
  }

  // ❌ Không biết user nào online, không broadcast status change
}
```

### Phát hiện

```regex
# Detect SessionConnectedEvent without matching SessionDisconnectEvent
@EventListener[\s\S]{0,200}SessionConnectedEvent(?![\s\S]{0,1000}SessionDisconnectEvent)

# Detect tasks/resources added on connect without cleanup
Map<.*>\s+\w+\s*=.*put\(.*sessionId(?![\s\S]{0,1000}remove\(.*sessionId)
```

### Checklist
- [ ] Implement `SessionRegistry` để track active sessions
- [ ] Listen `SessionDisconnectEvent` để cleanup resources
- [ ] Cancel scheduled tasks khi session disconnect
- [ ] Remove session từ maps (subscriptions, metadata)
- [ ] Broadcast user online/offline status changes
- [ ] Scheduled cleanup cho stale sessions (heartbeat timeout)
- [ ] Monitor active sessions qua metrics (Micrometer)
- [ ] Handle multiple tabs của cùng user (Set<sessionId>)

---

## Summary

| ID | Practice | Level | Key Benefit |
|:---|:---------|:-----:|:------------|
| 17.01 | STOMP over WebSocket | 🟠 | Protocol chuẩn, dễ routing/subscription |
| 17.02 | Authentication on handshake | 🔴 | Security - ngăn unauthorized access |
| 17.03 | Heartbeat/ping-pong | 🟠 | Detect dead connections sớm |
| 17.04 | Message size limit | 🔴 | Ngăn DoS attack, memory exhaustion |
| 17.05 | Reconnection strategy | 🟡 | UX - auto reconnect khi network issue |
| 17.06 | Broadcast throttling | 🟠 | Tránh overwhelm clients |
| 17.07 | Session cleanup | 🟠 | Tránh memory leak, resource leak |

### Quick Wins
1. ✅ Enable STOMP + SockJS fallback (17.01)
2. ✅ Add authentication interceptor (17.02)
3. ✅ Configure message size limit (17.04)

### Common Pitfalls
- ❌ Raw WebSocket handler thay vì STOMP
- ❌ Không authenticate handshake → security hole
- ❌ Broadcast high-frequency events không throttle → client lag
- ❌ Không cleanup resources on disconnect → memory leak

### Integration Points
- **Spring Security:** Authentication/authorization cho WebSocket
- **Micrometer:** Metrics cho active sessions, message rate
- **Redis:** Shared session registry trong multi-instance deployment
- **RabbitMQ/ActiveMQ:** External message broker cho scalability
