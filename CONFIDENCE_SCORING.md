# 📊 Confidence Scoring System - Giải Thích

## ❓ Confidence là gì?

**Confidence** (độ tin cậy) là **xác suất** parameter đó có SSRF vulnerability, từ **0.0** (không có dấu hiệu) đến **1.0** (chắc chắn 100%).

## 🎯 Cách Tool Tính Confidence

### Method 1: Behavioral Indicators (Quan sát hành vi)

Tool gửi **14 test payloads** khác nhau và quan sát response:

```python
TEST_PAYLOADS = [
    'http://example.com',           # External URL
    'http://127.0.0.1',             # Localhost
    'http://169.254.169.254',       # AWS metadata
    'file:///etc/passwd',           # File protocol
    'dict://localhost:6379',        # Redis protocol
    'http://host.docker.internal',  # Docker host
    # ... total 14 payloads
]
```

### Scoring System:

| Indicator | Score | Ý nghĩa |
|-----------|-------|---------|
| **Timeout** | +0.30 | Service đang cố connect tới external URL → HIGH probability |
| **Error Message** | +0.25 | "connection refused", "timeout", "DNS error" → Service thử fetch URL |
| **Connection Error** | +0.20 | Network error khi test → Service attempting external request |
| **Response Diff** | +0.15 | Response thay đổi theo payload → Service xử lý parameter |
| **Payload Reflected** | +0.10 | URL xuất hiện trong response → Có thể bị reflected |

### Formula:

```python
total_score = sum(all_indicator_scores)
confidence = min(total_score / total_payloads, 1.0)
# confidence = total_score / 14
```

---

### Method 2: Parameter Name Analysis (Phân tích tên)

Một số tên parameter **CỰC KỲ NGUY HIỂM** theo kinh nghiệm:

#### 🔥 Critical Names (Confidence: 0.6)
```python
callback_url, callbackUrl
webhook_url, webhookUrl
redirect_url, redirectUrl
notify_url, notifyUrl
```

**Lý do**: Đây là các parameter thiết kế **CHÍNH XÁC** để fetch external URLs!

#### ⚠️ High-Risk Names (Confidence: 0.35)
```python
url, uri, path
callback, webhook, redirect
target_url, targetUrl
fetch, load, import
```

**Lý do**: Thường được dùng để xử lý URLs

---

## 📊 Confidence Levels

### 🔴 CRITICAL: 0.7 - 1.0
```
🔥 High-probability SSRF
```
**Dấu hiệu:**
- Multiple timeouts khi test
- Error messages rõ ràng ("connection refused")
- Response thay đổi đáng kể
- **Ví dụ**: 
  - 4 payloads timeout → 4 × 0.3 / 14 = **0.86**
  - 2 timeouts + 3 errors → (2×0.3 + 3×0.25) / 14 = **0.73**

**Action**: 🚨 ƯU TIÊN CAO! Test callback ngay

---

### 🟠 HIGH: 0.5 - 0.69
```
⚠️ Likely SSRF parameter
```
**Dấu hiệu:**
- Một số timeouts hoặc errors
- Parameter name critical (`callback_url`)
- **Ví dụ**:
  - `callback_url` detected → **0.60**
  - 1 timeout + 2 errors → (0.3 + 2×0.25) / 14 = **0.57**

**Action**: ⚡ Test callback để confirm

---

### 🟡 MEDIUM: 0.3 - 0.49
```
🔍 Suspicious SSRF parameter
```
**Dấu hiệu:**
- Parameter name high-risk (`url`, `uri`, `redirect`)
- Một vài response differences
- **Ví dụ**:
  - `url` parameter detected → **0.35**
  - 2 response_diff + 1 reflected → (2×0.15 + 0.1) / 14 = **0.29** → 0.35 với name bonus

**Action**: 🔍 Worth testing

---

### 🟢 LOW: 0.1 - 0.29
```
💡 Potential SSRF by name
```
**Dấu hiệu:**
- Tên parameter có chứa keywords (`target`, `link`, `feed`)
- Rất ít behavioral indicators
- **Ví dụ**:
  - `image_url` detected → **0.15**
  - Minor response diff → 0.15 / 14 = **0.01** → 0.15 với name bonus

**Action**: 💡 Low priority, test if có thời gian

---

### ⚪ IGNORED: < 0.1
```
ℹ️ Not reported as finding
```
Chỉ log vào console, không hiển thị trong Findings panel

---

## 🎯 Ví Dụ Thực Tế

### Case 1: `callback_url` parameter

#### Trước Fix (Confidence: 0.04):
```
❌ Test 14 payloads:
  - No timeout
  - No error messages
  - Response giống nhau
  - No reflection

Score = 0 / 14 = 0.0
+ Minor noise = 0.04

Severity: LOW
Message: "Suspicious parameter: callback_url (confidence: 0.04)"
```

**Vấn đề**: Quá thấp! Đây là tên parameter CỰC KỲ NGUY HIỂM!

---

#### Sau Fix (Confidence: 0.60):
```
✅ Critical name detected: "callback_url"
Matches: ['callback_url', 'webhookUrl', 'redirect_url']

Confidence = 0.60 (based on name)

Severity: HIGH
Message: "⚠️ Likely SSRF parameter: callback_url (confidence: 0.60)"
```

**Tốt hơn**: Reflect đúng mức độ nguy hiểm dựa trên tên!

---

### Case 2: Unknown parameter với timeout

```
Test parameter: "fetch_url" (not in keyword list)

Test results:
  - Payload 1 (http://169.254.169.254): TIMEOUT → +0.30
  - Payload 2 (http://localhost): Connection error → +0.20
  - Payload 3 (file:///etc/passwd): Error message → +0.25

Score = 0.30 + 0.20 + 0.25 = 0.75
Confidence = 0.75 / 14 = 0.05... wait, this is wrong!

Actually: 0.75 (total indicators for 3 findings)
Not divided by total tests (that was old logic)

New logic: Score directly = 0.75

Severity: CRITICAL
Message: "🔥 High-probability SSRF: fetch_url (confidence: 0.75)"
```

---

## 💡 Tại Sao Callback Test Vẫn Cần Thiết?

**Confidence chỉ là DỰ ĐOÁN**, không phải **PROOF**:

| Confidence | Meaning | Confirmed? |
|-----------|---------|------------|
| 0.04 → 0.60 | Suspicious by name | ❌ No |
| 0.75 | Behavioral indicators | ❌ No |
| **1.0** | **Callback received** | ✅ **YES!** |

**Chỉ có Callback Test** mới **100% confirm** SSRF:
```
✅ CONFIRMED SSRF via callback_url
   Received callback from target server
   → VULNERABILITY PROVEN
```

---

## 🔧 Configuration

Nếu muốn adjust thresholds:

```python
# In web_ui/app.py

if confidence >= 0.7:    # Adjust these values
    severity = 'CRITICAL'
elif confidence >= 0.5:
    severity = 'HIGH'
elif confidence >= 0.3:
    severity = 'MEDIUM'
elif confidence >= 0.1:
    severity = 'LOW'
```

---

## 📖 Best Practices

### Ưu tiên test theo confidence:

1. **CRITICAL (0.7+)**: Test ngay lập tức
2. **HIGH (0.5+)**: Test trong vòng 10 phút
3. **MEDIUM (0.3+)**: Test nếu có thời gian
4. **LOW (0.1+)**: Test cuối cùng hoặc skip

### Don't trust confidence blindly:

- **False Positive**: `url=` query string trong blog → High confidence nhưng không vulnerable
- **False Negative**: Well-coded SSRF với error handling tốt → Low confidence nhưng vulnerable
- **Always callback test** để confirm!

---

## 🎓 Summary

**Confidence = Probability, NOT Proof**

- **Name-based**: `callback_url` → 0.60 (HIGH)
- **Behavior-based**: Timeouts/Errors → 0.30-0.75
- **Combined**: Name + Behavior → Highest confidence
- **Confirmed**: Callback received → 1.0 (CRITICAL)

**Tool sẽ giờ report đúng hơn:**
```
Before: "Suspicious parameter: callback_url (confidence: 0.04)" LOW
After:  "⚠️ Likely SSRF parameter: callback_url (confidence: 0.60)" HIGH
```

🎯 **Happy Hunting!**
