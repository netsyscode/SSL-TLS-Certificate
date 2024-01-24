
const taskId = window.location.pathname.split('/').pop(); // 从 URL 中获取任务ID

function checkStatus() {
    // 向后端发送获取状态的请求
    fetch('/scan_status/' + taskId)
    .then(response => {
        if (!response.ok) {
            throw new Error('Network response was not ok');
        }
        return response.json();
    })
    .then(data => {
        // 更新页面上的状态信息
        document.getElementById('status').innerHTML = data.status;

        // 如果任务未完成，继续轮询
        if (data.status !== 'completed') {
            setTimeout(checkStatus, 1000); // 1秒后再次检查状态
        }
    })
    .catch(error => {
        console.error('Error checking status:', error);
    });
}

// 初次加载页面时开始检查状态
document.addEventListener('DOMContentLoaded', checkStatus);

