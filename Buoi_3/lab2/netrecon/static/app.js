const form = document.getElementById('scan-form');
const results = document.getElementById('results');
form.addEventListener('submit', async (event) => {
  event.preventDefault();
  const button = form.querySelector('button');
  button.disabled = true;
  results.textContent = 'Đang xử lý…';
  try {
    const response = await fetch(form.action, { method: 'POST', body: new FormData(form) });
    if (response.ok || response.status === 400) {
      results.innerHTML = await response.text();
    } else {
      results.textContent = 'Có lỗi máy chủ khi xử lý yêu cầu.';
    }
  } catch (error) {
    results.textContent = 'Không kết nối được tới ứng dụng.';
  } finally {
    button.disabled = false;
  }
});
