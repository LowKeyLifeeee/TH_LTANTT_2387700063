# Lab 06 — Bảo mật với DevSecOps

Dự án Docusaurus theo mẫu classic mặc định, kèm các pipeline thực hành GitLab CI/CD.

Đọc **[HUONG_DAN_LAB.md](HUONG_DAN_LAB.md)** để tạo repository GitLab, chạy lần lượt từng pipeline và thu thập minh chứng.

## Chạy trên máy

```powershell
npm.cmd ci
npm.cmd run build
npm.cmd run serve
```

## Các cấu hình

- `ci-examples/01-basic.yml`: build, hai job test, deploy mô phỏng.
- `ci-examples/02-first-job.yml`: thông báo và ngày giờ.
- `ci-examples/03-build.yml`: build Docusaurus, lưu artifact.
- `ci-examples/04-pages.yml`: build và triển khai Pages.
- `.gitlab-ci.yml`: giống cấu hình cuối `04-pages.yml`.

Mã nguồn website nằm ngay gốc dự án theo đề bài. `docusaurus.config.js` lấy URL triển khai từ `PAGES_URL` hoặc `CI_PAGES_URL`, mặc định localhost khi chạy cục bộ. `npm ci` cần lockfile đã được commit.

Pipeline cuối dành cho GitLab hiện tại, dùng `pages: true`, chỉ xuất bản nhánh mặc định. Chưa có repository từ xa thì chưa thể xác nhận pipeline hoặc Pages đã triển khai thành công.
