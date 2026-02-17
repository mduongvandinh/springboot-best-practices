# Spring Boot Best Practices Skill

**174 best practices | 19 domains | Scoring 0-100 | Vietnamese**

Bộ công cụ tự động quét mã nguồn Spring Boot, đánh giá mức tuân thủ **174 best practices** trong **19 lĩnh vực**, chấm điểm 0-100 mỗi domain với trọng số. Hỗ trợ cả **Claude Code** và **Google Antigravity**.

> Bổ sung cho [Engineering Failures Audit Skill](https://github.com/mduongvandinh/engineering-failures/) — skill này **đề xuất chuẩn mực** (proactive), còn Engineering Failures **phát hiện lỗi** (reactive).

---

## Mục lục

- [Cài đặt](#cài-đặt)
  - [Claude Code](#claude-code)
  - [Google Antigravity](#google-antigravity)
- [Sử dụng](#sử-dụng)
  - [Claude Code](#sử-dụng-trong-claude-code)
  - [Google Antigravity](#sử-dụng-trong-google-antigravity)
- [19 Lĩnh vực](#19-lĩnh-vực)
- [Mức độ & Chấm điểm](#mức-độ--chấm-điểm)
- [Cấu trúc dự án](#cấu-trúc-dự-án)
- [Format mỗi best practice](#format-mỗi-best-practice)
- [Giấy phép](#giấy-phép)

---

## Cài đặt

### Claude Code

**Cách 1: Clone trực tiếp**

```bash
git clone https://github.com/mduongvandinh/springboot-best-practices.git \
  ~/.claude/skills/springboot-best-practices
```

**Cách 2: Copy thủ công**

```bash
cp -r springboot-best-practices/ ~/.claude/skills/springboot-best-practices/
```

**Xác nhận cài đặt:**

```bash
ls ~/.claude/skills/springboot-best-practices/
# springboot-best-practices.skill  knowledge/  README.md
```

### Google Antigravity

**Bước 1: Clone**

```bash
git clone https://github.com/mduongvandinh/springboot-best-practices.git \
  ~/.gemini/antigravity/skills/springboot-best-practices
```

**Bước 2: Chuyển đổi cấu trúc**

```bash
cd ~/.gemini/antigravity/skills/springboot-best-practices

# Đổi skill file → SKILL.md
mv springboot-best-practices.skill SKILL.md

# Đổi knowledge/ → references/
mv knowledge references
```

**Bước 3: Thêm metadata vào đầu SKILL.md**

Mở `SKILL.md` và thêm header:

```markdown
---
name: Spring Boot Best Practices
description: Quét và chấm điểm dự án Spring Boot theo 174 best practices, 19 domains. Tự động phát hiện vi phạm và đề xuất cải thiện.
---

(... giữ nguyên nội dung phía dưới ...)
```

**Bước 4 (tuỳ chọn): Tạo workflow trigger `/sbp`**

Tạo file `~/.gemini/antigravity/global_workflows/sbp.md`:

```markdown
---
name: Spring Boot Best Practices Audit
description: Quét và chấm điểm Spring Boot project
---

Đọc tất cả references trong skill springboot-best-practices,
sau đó quét source code trong workspace hiện tại và chấm điểm
theo 174 practices, 19 domains. Xuất báo cáo chi tiết.
```

**Xác nhận cài đặt:**

```bash
ls ~/.gemini/antigravity/skills/springboot-best-practices/
# SKILL.md  references/  README.md
```

> **Lưu ý:** Antigravity hỗ trợ Claude Sonnet 4.5 — bạn có thể chọn model Claude thay vì Gemini khi chạy audit.

---

## Sử dụng

### Sử dụng trong Claude Code

```bash
# Quét toàn bộ dự án
/springboot-best-practices

# Viết tắt
/sbp

# Chỉ quét domain cụ thể (01-19)
/sbp 06          # Chỉ quét Security
/sbp 05          # Chỉ quét JPA & Hibernate
/sbp 09          # Chỉ quét Testing

# Chỉ quét theo mức độ
/sbp mandatory    # Chỉ 56 practices BẮT BUỘC (🔴)
/sbp recommended  # Chỉ 82 practices KHUYẾN NGHỊ (🟠)

# Quét dự án khác (chỉ định đường dẫn)
/sbp all /path/to/other-project/src
```

**Báo cáo được lưu tại:**

```
~/.claude/skills/springboot-best-practices/reports/sbp-audit-YYYY-MM-DD-HHMMSS.md
```

### Sử dụng trong Google Antigravity

Trong agent chat, gõ trực tiếp:

```
Quét dự án Spring Boot theo best practices
```

Hoặc nếu đã tạo workflow (Bước 4 ở trên):

```
/sbp
```

Antigravity sẽ tự đọc references và quét workspace hiện tại.

---

## 19 Lĩnh vực

| # | Lĩnh vực | Practices | 🔴 | 🟠 | 🟡 | Trọng số |
|---|----------|:---------:|:--:|:--:|:--:|:--------:|
| 01 | Cấu Trúc Dự Án | 9 | 2 | 3 | 4 | ×1 |
| 02 | Dependency Injection | 9 | 2 | 5 | 2 | ×1 |
| 03 | REST API & Controller | 10 | 4 | 4 | 2 | ×1 |
| 04 | Service Layer | 8 | 3 | 4 | 1 | ×1 |
| 05 | JPA & Hibernate | 12 | 4 | 6 | 2 | **×2** |
| 06 | Security | 12 | 8 | 3 | 1 | **×3** |
| 07 | Exception Handling | 9 | 3 | 5 | 1 | ×1 |
| 08 | Logging & Monitoring | 9 | 1 | 5 | 3 | ×1 |
| 09 | Testing | 10 | 4 | 3 | 3 | **×2** |
| 10 | Caching | 8 | 2 | 3 | 3 | ×1 |
| 11 | Async & Messaging | 10 | 2 | 6 | 2 | ×1 |
| 12 | Validation | 10 | 3 | 5 | 2 | ×1 |
| 13 | Configuration | 8 | 2 | 3 | 3 | ×1 |
| 14 | Migration | 8 | 4 | 3 | 1 | ×1 |
| 15 | Deployment | 9 | 3 | 4 | 2 | ×1 |
| 16 | Spring Cloud | 8 | 2 | 5 | 1 | ×1 |
| 17 | WebSocket | 7 | 2 | 4 | 1 | ×1 |
| 18 | Email & Notification | 8 | 2 | 4 | 2 | ×1 |
| 19 | File Storage | 10 | 3 | 4 | 3 | ×1 |
| | **Tổng** | **174** | **56** | **82** | **36** | |

---

## Mức độ & Chấm điểm

### 3 mức độ vi phạm

| Mức | Ý nghĩa | Điểm trừ |
|-----|---------|:---------:|
| 🔴 BẮT BUỘC | Vi phạm gây rủi ro nghiêm trọng. Phải tuân thủ. | **-10** |
| 🟠 KHUYẾN NGHỊ | Nên tuân thủ để đảm bảo chất lượng. | **-5** |
| 🟡 NÊN CÓ | Cải thiện thêm, áp dụng khi có thời gian. | **-2** |

### Công thức tính điểm

```
Domain Score = max(0, 100 - Σ(violation_penalty))
Overall Score = Σ(domain_score × weight) / Σ(weight)

Trọng số: Security ×3, JPA ×2, Testing ×2, còn lại ×1
```

### Xếp hạng

| Điểm | Xếp hạng |
|:-----:|----------|
| 90-100 | XUẤT SẮC |
| 75-89 | TỐT |
| 60-74 | TRUNG BÌNH |
| 40-59 | YẾU |
| 0-39 | NGUY HIỂM |

---

## Cấu trúc dự án

```
springboot-best-practices/
├── springboot-best-practices.skill    # Skill definition (Claude Code)
├── README.md                          # File này
├── knowledge/                         # 20 knowledge files
│   ├── 00_Tong_Quan.md                #   Tổng quan & mục lục
│   ├── 01_Cau_Truc_Du_An.md           #   9 practices
│   ├── 02_Dependency_Injection.md     #   9 practices
│   ├── 03_REST_API_Controller.md      #   10 practices
│   ├── 04_Service_Layer.md            #   8 practices
│   ├── 05_JPA_Hibernate.md            #   12 practices (×2)
│   ├── 06_Security.md                 #   12 practices (×3)
│   ├── 07_Exception_Handling.md       #   9 practices
│   ├── 08_Logging_Monitoring.md       #   9 practices
│   ├── 09_Testing.md                  #   10 practices (×2)
│   ├── 10_Caching.md                  #   8 practices
│   ├── 11_Async_Messaging.md          #   10 practices
│   ├── 12_Validation.md               #   10 practices
│   ├── 13_Configuration.md            #   8 practices
│   ├── 14_Migration.md                #   8 practices
│   ├── 15_Deployment.md               #   9 practices
│   ├── 16_Spring_Cloud.md             #   8 practices
│   ├── 17_WebSocket.md                #   7 practices
│   ├── 18_Email_Notification.md       #   8 practices
│   └── 19_File_Storage.md             #   10 practices
└── reports/                           # Audit reports (auto-generated)
```

### Thống kê

| Thành phần | Số lượng |
|------------|:--------:|
| Knowledge files | 20 (00-19) |
| Tổng dòng knowledge | 46,754 |
| Skill file | 226 dòng |
| **Tổng toàn bộ** | **~47,100 dòng** |

---

## Format mỗi best practice

Mỗi practice có **6 phần**:

```markdown
## SBP-XX-YY: Tên practice

**Metadata:** Mã số | Mức độ (🔴/🟠/🟡) | Điểm trừ | Tags

### Tại sao?
Giải thích 3-5 câu: tại sao quan trọng + hậu quả nếu vi phạm.

### Cách đúng
10-30 dòng Java code mẫu.

### Cách sai
5-15 dòng anti-pattern cần tránh.

### Phát hiện
Regex patterns (ripgrep-compatible) để tự động phát hiện vi phạm.

### Checklist
Danh sách kiểm tra nhanh.
```

---

## Bộ đôi Complementary Skills

| Skill | Vai trò | Patterns | Link |
|-------|---------|:--------:|------|
| Engineering Failures | **Reactive** — phát hiện lỗi | 137 | [GitHub](https://github.com/mduongvandinh/engineering-failures) |
| **Spring Boot Best Practices** | **Proactive** — đề xuất chuẩn mực | 174 | [GitHub](https://github.com/mduongvandinh/springboot-best-practices) |

Nên chạy **cả hai** để có đánh giá toàn diện nhất cho dự án Spring Boot.

---

## Yêu cầu

- **Claude Code** hoặc **Google Antigravity**
- Dự án Spring Boot 3.x / Java 17+
- Nội dung tiếng Việt (có dấu)

## Giấy phép

Nội dung tổng hợp từ Spring Documentation, Baeldung, Vlad Mihalcea, OWASP.
Tự do sử dụng và phân phối.

## Tác giả

- GitHub: [@mduongvandinh](https://github.com/mduongvandinh)
