# Assistant TODO (có thể chỉnh sửa)

Tệp này chứa danh sách TODO do trợ lý tạo. Bạn có thể chỉnh sửa trực tiếp file này bằng VS Code; sau khi chỉnh sửa xong, gửi cho trợ lý lệnh "import todo" để tôi cập nhật lại trạng thái trong công cụ quản lý TODO.

## Danh sách TODO hiện tại

- [ ] Export current TODO to file
  - Mô tả: Ghi danh sách TODO hiện tại vào `ASSISTANT_TODO.md` trong gốc repo để người dùng chỉnh sửa.
- [ ] Allow manual edits and reimport
  - Mô tả: Hướng dẫn cách chỉnh sửa file và yêu cầu trợ lý nhập lại trạng thái TODO từ nội dung file.
- [x] Keep replies in Vietnamese
  - Mô tả: Đảm bảo trợ lý luôn trả lời bằng tiếng Việt cho phiên làm việc này.

---

Hướng dẫn sử dụng nhanh

1. Mở file này trong VS Code và chỉnh sửa nội dung TODO như bạn muốn.
   - PowerShell (mở repo trong VS Code):

```powershell
cd C:\Users\ASUS-PRO\Desktop\microservice_pentest_toolkit; code .\ASSISTANT_TODO.md
```

2. Sau khi chỉnh sửa xong, quay lại chat và gửi: `import todo` (hoặc yêu cầu tôi "đọc file TODO"), tôi sẽ đọc file và cập nhật trạng thái trong công cụ `manage_todo_list`.

3. Nếu muốn, tôi cũng có thể tự động commit file này vào git (hãy cho phép nếu bạn muốn).

Ghi chú: Trạng thái thực sự của TODO được lưu trong công cụ nội bộ `manage_todo_list`. File này chỉ là bản sao để bạn dễ chỉnh sửa và lưu trữ lâu dài.
