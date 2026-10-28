# Lab 06 với GitHub Actions

Bản này chuyển phần thực hành sang GitHub Actions và GitHub Pages do GitLab yêu cầu xác minh tài khoản. Đề gốc yêu cầu GitLab CI/CD; cần giảng viên chấp nhận nền tảng thay thế khi nộp bài.

Repository sử dụng: https://github.com/LowKeyLifeeee/TH_LTANTT_2387700063

Mã nguồn Docusaurus nằm trong `Buoi_6/`. Workflow thực thi phải nằm ở `.github/workflows/` tại gốc repository. Các bản trong `Buoi_6/.github/workflows/` chỉ là bản lưu cấu hình.

## Pipeline cơ bản

Mở Actions > Basic pipeline lab > Run workflow > main > Run workflow. Pipeline có `build-job`, `test-job1`, `test-job2`, `deploy-prod`. Hai job test phụ thuộc build và chạy song song; job thứ hai chờ thêm 20 giây. Deploy chỉ mô phỏng bằng thông báo. Chụp sơ đồ các job và log deploy sau khi chạy thành công.

## Build và Pages

Trong Settings > Pages, chọn Source là GitHub Actions. Workflow Build and deploy Docusaurus tự chạy khi có thay đổi Buoi_6 trên main, hoặc chọn Run workflow trong Actions. Job build chạy `npm ci` và `npm run build` tại Buoi_6 rồi upload thư mục build làm artifact. Job deploy phụ thuộc build, dùng quyền Pages và OIDC để xuất bản.

Địa chỉ dự kiến: https://lowkeylifeeee.github.io/TH_LTANTT_2387700063/

Lấy URL thực tế từ kết quả job deploy hoặc Settings > Pages. Workflow truyền biến PAGES_URL để Docusaurus tạo đúng đường dẫn tài nguyên. Cấu hình này phục vụ website bài 6 tại đường dẫn của repository, không đặt thêm `/Buoi_6/` vào URL.

Chụp kết quả build, artifact, sơ đồ hai job và website đang chạy để làm minh chứng. Các log của workflow Basic pipeline lab thay thế phần minh chứng pipeline cơ bản của GitLab.

## Chi phí và phạm vi

Workflow dùng runner tiêu chuẩn ubuntu-24.04. Theo GitHub Docs, runner tiêu chuẩn miễn phí cho repository public; GitHub Pages khả dụng với repository public trên gói Free. Artifact Pages được giữ 1 ngày. Không bật runner lớn hoặc dịch vụ trả phí để thực hiện bài này. Nếu repository private và tài khoản Free, cần quyết định công khai kho hoặc chọn phương án hosting khác trước khi dùng Pages.

Các cảnh báo phụ thuộc đã ghi ở HUONG_DAN_LAB.md vẫn áp dụng. Các pipeline trong bài mô phỏng CI/CD và triển khai website; chưa bổ sung SAST, DAST, quét container hoặc IaC.

Tham khảo: https://docs.github.com/en/pages/getting-started-with-github-pages/using-custom-workflows-with-github-pages và https://docs.github.com/en/actions/concepts/billing-and-usage
