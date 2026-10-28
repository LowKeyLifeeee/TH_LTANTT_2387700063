# Hướng dẫn thực hành Lab 06

Bài thực hành gồm pipeline cơ bản có 4 job và pipeline build Docusaurus rồi triển khai GitLab Pages. Các file trong `ci-examples/` lưu từng bước trung gian; `.gitlab-ci.yml` là cấu hình cuối cùng.

## 1. Chạy thử trên máy

Mở PowerShell trong thư mục dự án, dùng Node.js 24:

```powershell
npm.cmd ci
npm.cmd run build
npm.cmd run serve
```

Mở địa chỉ được terminal hiển thị. Nhấn Ctrl+C để dừng. `build/` là kết quả build, không cần đưa vào Git vì pipeline tự tạo lại.

## 2. Tạo repository GitLab riêng

1. Đăng nhập https://gitlab.com bằng tài khoản của bạn.
2. Chọn New project > Create blank project.
3. Đặt tên `lab-06-devsecops`, chọn namespace cá nhân. Có thể chọn Private; chỉ chọn Public nếu muốn công khai mã nguồn.
4. Chọn Initialize repository with a README rồi Create project.
5. Sao chép URL HTTPS ở Code > Clone with HTTPS.
6. Clone vào một thư mục mới nằm ngoài kho bài tập hiện tại, ví dụ:

```powershell
git clone https://gitlab.com/TEN_CUA_BAN/lab-06-devsecops.git D:\lab-06-gitlab
```

Thay `TEN_CUA_BAN` bằng username thật. Thư mục `Buoi_6` hiện nằm trong một kho Git của thư mục cha; không đổi remote kho cha và không chạy `git init` bên trong `Buoi_6`.

Sao chép mã nguồn từ `Buoi_6` sang thư mục vừa clone bằng Explorer, bao gồm `.gitignore`, `.gitlab-ci.yml`, `package.json`, `package-lock.json`, cấu hình Docusaurus, các thư mục `src`, `docs`, `blog`, `static`, `ci-examples` và hướng dẫn này. Không sao chép `node_modules`, `.docusaurus`, `build`, `public` hoặc bất kỳ thư mục `.git` nào. Ghi đè README mẫu nếu cần.

## 3. Pipeline cơ bản

Trong PowerShell tại `D:\lab-06-gitlab`, thực hiện:

```powershell
Copy-Item ci-examples\01-basic.yml .gitlab-ci.yml
git add .
git commit -m "Lab 06: basic build test deploy pipeline"
git push origin HEAD
```

Vào Settings > CI/CD > Runners, kiểm tra có runner Linux khả dụng. Trong Build > Pipelines, chờ pipeline thành công. Pipeline này có ba stage, bốn job; hai job test có thể chạy song song tùy số runner. `test-job2` chờ thêm 20 giây. `deploy-prod` chỉ in thông báo mô phỏng, chưa triển khai website.

Chụp pipeline và log `deploy-prod` để ghi nhận kết quả thực tế.

## 4. Pipeline Docusaurus theo từng bước

Chạy lần lượt từng nhóm lệnh và chờ pipeline của nhóm đó hoàn tất trước khi chuyển bước.

Job đầu tiên:

```powershell
Copy-Item ci-examples\02-first-job.yml .gitlab-ci.yml
git add .gitlab-ci.yml
git commit -m "Lab 06: first job and date"
git push origin HEAD
```

Kiểm tra log có `This is my first job!` và ngày giờ.

Job build:

```powershell
Copy-Item ci-examples\03-build.yml .gitlab-ci.yml
git add .gitlab-ci.yml
git commit -m "Lab 06: build Docusaurus and save artifacts"
git push origin HEAD
```

Mở `build-job`, xác nhận thành công và dùng Browse artifacts để xem `build/index.html` cùng các tài nguyên.

Triển khai Pages:

```powershell
Copy-Item ci-examples\04-pages.yml .gitlab-ci.yml
git add .gitlab-ci.yml
git commit -m "Lab 06: deploy Docusaurus to GitLab Pages"
git push origin HEAD
```

Pipeline cuối có `build-job` ở stage build và `pages` ở stage deploy. GitLab tải artifact từ build, sau đó chuyển `build/` thành `public/`. Job Pages chỉ chạy trên nhánh mặc định. Nếu build thất bại, deploy sẽ không chạy.

Vào Deploy > Pages để lấy URL chính xác. Nếu cần URL dạng `https://username.gitlab.io/lab-06-devsecops/` như tài liệu, tắt Use unique domain nếu có rồi chạy lại pipeline để build theo URL mới. Cấu hình website lấy `url` và `baseUrl` từ `CI_PAGES_URL`; không cần ghi username vào mã nguồn. Có thể dùng biến `PAGES_URL` để chỉ định URL khi chạy build trên máy.

## 5. Minh chứng để nộp

- URL repository GitLab và URL Pages thực tế.
- Ảnh pipeline cơ bản với 4 job thành công.
- Ảnh log job đầu tiên có thông báo và ngày giờ.
- Ảnh log build và danh sách artifact `build/`.
- Ảnh pipeline cuối và màn hình Deploy > Pages.
- Ảnh website Docusaurus đã mở từ URL GitLab Pages.

Các minh chứng phải lấy từ lần chạy thật. Build cục bộ thành công không thay thế kết quả pipeline trên GitLab.

## 6. Giải thích để trình bày bài

CI tự động chạy công việc khi có commit. CD đưa kết quả build lên môi trường phục vụ. Stage quyết định thứ tự; job cùng stage có thể chạy song song. Artifact là file kết quả được lưu lại để job sau dùng, khác cache chủ yếu nhằm tăng tốc cài đặt.

Theo phần lý thuyết của bài, bảo vệ pipeline cần phân quyền ít nhất, MFA, quản lý secrets ngoài mã nguồn, ký commit và artifact, kiểm thử tự động, giám sát log và cô lập runner. SAST phân tích mã nguồn; DAST kiểm tra ứng dụng đang chạy; SCA kiểm tra thư viện; secret scanning phát hiện bí mật bị lộ. IaC scanning phát hiện cấu hình hạ tầng không an toàn trước triển khai.

Pipeline thực hành trong tài liệu tập trung build và Pages, chưa có SAST, DAST, quét container hoặc IaC. Các file của bài giữ đúng phạm vi đó; không được coi pipeline này là đã triển khai đầy đủ mọi biện pháp DevSecOps. `npm ci` sử dụng lockfile để cài phụ thuộc nhất quán; Pages chỉ triển khai từ nhánh mặc định. Thiết lập protected branch, quyền runner và MFA cần thực hiện trong tài khoản GitLab.

## 7. Xử lý lỗi

- Job Pending: kiểm tra runner được bật, quota compute và yêu cầu xác minh tài khoản mà GitLab hiển thị.
- `npm ci` lỗi: bảo đảm đã commit `package-lock.json` khớp `package.json`.
- Không có pipeline: kiểm tra `.gitlab-ci.yml` nằm ngay gốc repository mới, không nằm trong thư mục `Buoi_6/`.
- Pages 404 hoặc mất CSS: kiểm tra URL ở Deploy > Pages, chạy lại pipeline sau khi đổi domain, kiểm tra `CI_PAGES_URL` hoặc biến ghi đè `PAGES_URL`.
- YAML không hợp lệ: mở Build > Pipeline editor > Validate để kiểm tra bằng GitLab CI Lint.
- Push yêu cầu xác thực: đăng nhập qua trình quản lý Git credential hoặc dùng token theo hướng dẫn GitLab; không ghi token vào file hoặc URL đã lưu.

## Tài liệu đối chiếu

- Đề bài: `D:\lab-06.docx`.
- https://docs.gitlab.com/ci/quick_start/tutorial/
- https://docs.gitlab.com/ci/yaml/
- https://docusaurus.io/docs/installation
- https://docusaurus.io/docs/deployment

## Lưu ý về phụ thuộc khi kiểm tra bài

Lần kiểm tra ngày 28/10/2026 với mẫu Docusaurus 3.10.2, `npm audit` báo 25 mục bị ảnh hưởng (3 low, 6 moderate, 1 high, 15 critical, bao gồm các package bị ảnh hưởng gián tiếp). Các cảnh báo nằm trong cây công cụ build/development, gồm `tinypool`, `serialize-javascript`, `uuid` và `deepmerge`. Đây không phải kết luận rằng có 25 lỗ hổng độc lập trên website tĩnh.

Không chạy `npm audit fix --force` một cách máy móc: kết quả audit đề xuất đổi Docusaurus xuống 3.7.0, có thể làm thay đổi mẫu và tính tương thích. Bản bài lab giữ nguyên phiên bản template để thực hiện đúng các bước; các cảnh báo này chưa được khắc phục. Khi dùng cho dự án thật, cần đánh giá advisory, cập nhật các phiên bản tương thích và kiểm tra lại build trước triển khai. Chạy `npm.cmd audit` để lấy kết quả mới nhất.
