# 📚 DOCUMENTATION INDEX

## 🎯 **QUICK NAVIGATION**

### **🚀 Getting Started**
1. **[README.md](README.md)** - Tổng quan và tính năng chính
2. **[SUMMARY.md](SUMMARY.md)** - Tóm tắt toàn bộ dự án
3. **[quick_start.py](quick_start.py)** - Demo nhanh (run ngay!)

### **📖 User Documentation**
4. **[USAGE_GUIDE.md](USAGE_GUIDE.md)** - Hướng dẫn chi tiết từng bước
5. **[config.example.json](config.example.json)** - Ví dụ cấu hình

### **🏗️ Developer Documentation**
6. **[ARCHITECTURE.md](ARCHITECTURE.md)** - Kiến trúc và design decisions

---

## 📋 **CHỌN ĐỌC THEO MỤC ĐÍCH**

### **Nếu bạn là USER (muốn dùng tool):**

```
1. Đọc README.md           → Hiểu tổng quan
2. Run quick_start.py      → Demo nhanh
3. Đọc USAGE_GUIDE.md      → Học cách dùng
4. Run cli.py              → Thực chiến
```

**Thời gian**: 30 phút

---

### **Nếu bạn là DEVELOPER (muốn hiểu/mở rộng code):**

```
1. Đọc SUMMARY.md          → Hiểu scope dự án
2. Đọc ARCHITECTURE.md     → Hiểu kiến trúc
3. Xem code trong core/    → Hiểu core components
4. Xem code trong modules/ → Hiểu business logic
5. Extend toolkit          → Thêm features
```

**Thời gian**: 2-3 giờ

---

### **Nếu bạn là SECURITY RESEARCHER:**

```
1. Đọc README.md           → Tổng quan
2. Run cli.py --mode all   → Full scan
3. Analyze findings.db     → Research patterns
4. Đọc ARCHITECTURE.md     → Hiểu detection logic
5. Contribute              → Thêm techniques
```

**Thời gian**: 1-2 giờ

---

## 📝 **FILE DESCRIPTIONS**

### **Core Files**

| File | Purpose | Audience |
|------|---------|----------|
| `cli.py` | Main entry point, orchestrator | All users |
| `quick_start.py` | Demo script | New users |
| `requirements.txt` | Python dependencies | All users |
| `__init__.py` | Package initialization | Developers |

### **Documentation Files**

| File | Content | Best For |
|------|---------|----------|
| `README.md` | Overview, features, quick start | First-time users |
| `SUMMARY.md` | Project summary, stats, roadmap | Quick overview |
| `USAGE_GUIDE.md` | Step-by-step guide, examples | Learning usage |
| `ARCHITECTURE.md` | Design, modules, extensions | Developers |
| `INDEX.md` | This file - navigation | All users |
| `config.example.json` | Config example | Configuration |

### **Core Modules**

| Module | Description | LOC |
|--------|-------------|-----|
| `core/config.py` | Configuration management | ~200 |
| `core/logger.py` | Colored logging system | ~150 |
| `core/database.py` | SQLite findings storage | ~250 |
| `core/reporter.py` | Report generator | ~100 |

### **Black Box Modules**

| Module | Description | LOC |
|--------|-------------|-----|
| `blackbox/reconnaissance/endpoint_discovery.py` | Endpoint fuzzing | ~200 |
| `blackbox/reconnaissance/parameter_fuzzer.py` | Parameter discovery | ~300 |
| `blackbox/detection/external_callback.py` | Callback server | ~350 |
| `blackbox/exploitation/internal_scan.py` | Internal network scan | ~250 |

### **Gray Box Modules**

| Module | Description | LOC |
|--------|-------------|-----|
| `graybox/architecture/docker_inspector.py` | Docker analysis | ~300 |

### **White Box Modules**

| Module | Description | LOC |
|--------|-------------|-----|
| `whitebox/static_analysis/code_scanner.py` | Code scanner (AST) | ~400 |

---

## 🎯 **COMMON TASKS**

### **Task 1: Run Quick Demo**
```bash
python quick_start.py
# Select option from menu
```
**Doc**: None needed (interactive)

---

### **Task 2: Black Box Scan**
```bash
python cli.py --mode blackbox --target http://localhost:8083/inventory/1/M
```
**Doc**: [USAGE_GUIDE.md#black-box-mode](USAGE_GUIDE.md)

---

### **Task 3: Gray Box with Docker**
```bash
python cli.py --mode graybox --docker
```
**Doc**: [USAGE_GUIDE.md#gray-box-mode](USAGE_GUIDE.md)

---

### **Task 4: White Box Code Scan**
```bash
python cli.py --mode whitebox --source-path ../microservice_lab
```
**Doc**: [USAGE_GUIDE.md#white-box-mode](USAGE_GUIDE.md)

---

### **Task 5: Full Pentest**
```bash
python cli.py --mode all \
  --target http://localhost:8083 \
  --source-path ../microservice_lab \
  --docker
```
**Doc**: [USAGE_GUIDE.md#combined-mode](USAGE_GUIDE.md)

---

### **Task 6: Add New Scanner**
**Doc**: [ARCHITECTURE.md#extension-points](ARCHITECTURE.md)

---

### **Task 7: Customize Config**
```bash
cp config.example.json my_config.json
# Edit my_config.json
python cli.py --config my_config.json
```
**Doc**: [config.example.json](config.example.json)

---

## 🔍 **FINDING SPECIFIC INFORMATION**

### **"Làm sao để..."**

| Question | Answer In |
|----------|-----------|
| ...cài đặt toolkit? | README.md - Installation |
| ...chạy Black Box scan? | USAGE_GUIDE.md - Black Box Mode |
| ...hiểu kiến trúc? | ARCHITECTURE.md |
| ...thêm scanner mới? | ARCHITECTURE.md - Extension Points |
| ...config custom settings? | config.example.json |
| ...xem findings? | USAGE_GUIDE.md - Analyze Results |
| ...export reports? | USAGE_GUIDE.md - Export Formats |

### **"Cái này là gì..."**

| Item | Explanation In |
|------|----------------|
| ...Black Box mode? | README.md - Features |
| ...Confidence score? | ARCHITECTURE.md - Black Box |
| ...Finding database? | ARCHITECTURE.md - Core Modules |
| ...Callback server? | ARCHITECTURE.md - Black Box |
| ...AST analysis? | ARCHITECTURE.md - White Box |
| ...Docker inspector? | ARCHITECTURE.md - Gray Box |

---

## 📖 **READING ORDER**

### **For Complete Understanding:**

```
Day 1: Overview
├─ README.md (20 min)
├─ SUMMARY.md (15 min)
└─ Run quick_start.py (15 min)

Day 2: Usage
├─ USAGE_GUIDE.md Part 1: Black Box (30 min)
├─ Run Black Box scan (30 min)
├─ USAGE_GUIDE.md Part 2: Gray Box (20 min)
└─ Run Gray Box scan (20 min)

Day 3: Deep Dive
├─ USAGE_GUIDE.md Part 3: White Box (30 min)
├─ Run White Box scan (30 min)
├─ ARCHITECTURE.md (60 min)
└─ Explore source code (60 min)

Day 4: Extend
├─ Study extension points (30 min)
├─ Add custom scanner (2 hours)
└─ Test and validate (1 hour)
```

**Total**: ~12 hours để master toolkit

---

## 🎓 **LEARNING PATH**

### **Beginner → Intermediate → Advanced**

```
BEGINNER (Day 1-2)
├─ Hiểu SSRF là gì
├─ Chạy được quick_start.py
├─ Chạy được Black Box scan
└─ Đọc và hiểu report

INTERMEDIATE (Day 3-5)
├─ Hiểu 3 modes khác nhau
├─ Chạy full scan
├─ Analyze findings trong database
├─ Customize config
└─ Hiểu architecture

ADVANCED (Week 2+)
├─ Đọc source code
├─ Hiểu design decisions
├─ Thêm custom scanner
├─ Contribute code
└─ Research new techniques
```

---

## 🔧 **TROUBLESHOOTING**

| Problem | Solution Doc | Section |
|---------|--------------|---------|
| Installation errors | README.md | Installation |
| Docker not found | USAGE_GUIDE.md | Troubleshooting |
| No findings detected | USAGE_GUIDE.md | Troubleshooting |
| Callback server port in use | USAGE_GUIDE.md | Troubleshooting |
| Config errors | config.example.json | Examples |

---

## 🌟 **HIGHLIGHTS**

### **Must-Read Sections:**

1. **README.md - Features Section** 
   → Hiểu toolkit có thể làm gì

2. **USAGE_GUIDE.md - Black Box Step-by-Step**
   → Học cách dùng basic

3. **ARCHITECTURE.md - Design Principles**
   → Hiểu tại sao thiết kế như vậy

4. **SUMMARY.md - Use Cases**
   → Áp dụng vào real world

---

## 📞 **NEED HELP?**

### **Resources:**

1. **Read Docs First** - Most questions answered here
2. **Run quick_start.py** - Interactive demo
3. **Check USAGE_GUIDE.md** - Step-by-step examples
4. **See ARCHITECTURE.md** - Technical details

### **Still Stuck?**

1. Check existing issues
2. Search documentation (Ctrl+F)
3. Create new issue với:
   - What you tried
   - What happened
   - What you expected
   - Error messages/logs

---

## 🎯 **NEXT STEPS**

### **After Reading Docs:**

1. ✅ Install dependencies
2. ✅ Run quick_start.py
3. ✅ Try Black Box scan
4. ✅ Try Gray Box (if Docker available)
5. ✅ Try White Box (if source available)
6. ✅ Analyze results
7. ✅ Customize for your needs
8. ✅ Contribute back!

---

## 📊 **DOCUMENTATION STATS**

| Doc | Words | Read Time | Complexity |
|-----|-------|-----------|------------|
| INDEX.md | 1,500 | 5 min | Easy |
| README.md | 2,500 | 10 min | Easy |
| SUMMARY.md | 3,000 | 12 min | Medium |
| USAGE_GUIDE.md | 4,000 | 20 min | Medium |
| ARCHITECTURE.md | 4,500 | 25 min | Hard |
| **TOTAL** | **15,500** | **72 min** | - |

---

**🎯 Happy Reading!** 📚

*Use this index to quickly find what you need!*
