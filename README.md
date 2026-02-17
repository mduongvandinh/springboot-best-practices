# Spring Boot Best Practices Skill
# Kỹ Năng Đánh Giá Chuẩn Mực Spring Boot

## Giới thiệu

Bộ công cụ tự động quét mã nguồn Spring Boot để đánh giá mức tuân thủ **174 best practices** trong **19 lĩnh vực**. Chấm điểm 0-100 mỗi domain với trọng số.

Bổ sung cho [Engineering Failures Audit Skill](../engineering-failures/) — skill này đề xuất chuẩn mực (proactive), còn Engineering Failures phát hiện lỗi (reactive).

## Cài đặt

### Cách 1: Copy thư mục

```bash
cp -r springboot-best-practices/ ~/.claude/skills/springboot-best-practices/
```

### Cách 2: Clone từ git

```bash
git clone <repo-url> ~/.claude/skills/springboot-best-practices/
```

### Xác nhận cài đặt

```bash
ls ~/.claude/skills/springboot-best-practices/
# Phải thấy: springboot-best-practices.skill, knowledge/, README.md
```

## Sử dụng

### Trong Claude Code

```bash
# Quét toàn bộ dự án
/springboot-best-practices

# Viết tắt
/sbp

# Chỉ quét domain cụ thể (01-19)
/sbp 06          # Chỉ quét Security
/sbp 05          # Chỉ quét JPA & Hibernate

# Chỉ quét theo mức độ
/sbp mandatory    # Chỉ practices BẮT BUỘC
/sbp recommended  # Chỉ practices KHUYẾN NGHỊ

# Quét dự án khác
/sbp all D:/other-project/src
```

## 19 Lĩnh vực

| # | Lĩnh vực | Số practices | 🔴 | 🟠 | 🟡 | Trọng số |
|---|----------|:------------:|:--:|:--:|:--:|:--------:|
| 01 | Cấu Trúc Dự Án | 9 | 2 | 3 | 4 | ×1 |
| 02 | Dependency Injection | 9 | 2 | 5 | 2 | ×1 |
| 03 | REST API & Controller | 10 | 4 | 4 | 2 | ×1 |
| 04 | Service Layer | 8 | 3 | 4 | 1 | ×1 |
| 05 | JPA & Hibernate | 12 | 4 | 6 | 2 | ×2 |
| 06 | Security | 12 | 8 | 3 | 1 | ×3 |
| 07 | Exception Handling | 9 | 3 | 5 | 1 | ×1 |
| 08 | Logging & Monitoring | 9 | 1 | 5 | 3 | ×1 |
| 09 | Testing | 10 | 4 | 3 | 3 | ×2 |
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

## Mức độ

| Mức | Ý nghĩa | Điểm trừ |
|-----|---------|:---------:|
| 🔴 BẮT BUỘC | Vi phạm gây rủi ro nghiêm trọng. Phải tuân thủ. | -10 |
| 🟠 KHUYẾN NGHỊ | Nên tuân thủ để đảm bảo chất lượng. | -5 |
| 🟡 NÊN CÓ | Cải thiện thêm, áp dụng khi có thời gian. | -2 |

## Hệ thống chấm điểm

```
Domain Score = max(0, 100 - Σ(violation_penalty))
Overall Score = Σ(domain_score × weight) / Σ(weight)

Trọng số: Security ×3, JPA ×2, Testing ×2, còn lại ×1
```

| Điểm | Xếp hạng |
|:-----:|----------|
| 90-100 | 🏆 XUẤT SẮC |
| 75-89 | ✅ TỐT |
| 60-74 | ⚠️ TRUNG BÌNH |
| 40-59 | 🟠 YẾU |
| 0-39 | 🔴 NGUY HIỂM |

## Format mỗi best practice

6 phần: Tên, Metadata (mã số + mức + tags), Tại sao?, Cách đúng ✅, Cách sai ❌, Phát hiện (regex).

## Báo cáo

Sau khi quét, báo cáo được lưu tại:
```
~/.claude/skills/springboot-best-practices/reports/sbp-audit-YYYY-MM-DD-HHMMSS.md
```

## Giấy phép

Nội dung tổng hợp từ Spring Documentation, Baeldung, Vlad Mihalcea, OWASP. Tự do sử dụng và phân phối.
