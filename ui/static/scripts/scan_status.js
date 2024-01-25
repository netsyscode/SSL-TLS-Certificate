
const taskId = window.location.pathname.split('/').pop(); // 从 URL 中获取任务ID

function checkStatus() {
    console.log("checking status")

    // 向后端发送获取状态的请求
    // fetch('/system/scan_status/' + taskId)
    fetch('/system/scan_status', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
    })

    .then(response => {
        if (!response.ok) {
            throw new Error('Network response was not ok');
        }
        return response.json();
    })
    .then(data => {

        document.getElementById('status').innerHTML = ``
        for (var key in data) {
            if (data.hasOwnProperty(key)) {
                // key 是当前的键
                var currentData = data[key];
        
                // 在这里你可以访问当前键对应的值
                var scanStatus = currentData["scan_status"];
                var scanTime = currentData["scan_time"];
                var scannedDomains = currentData["scanned_domains"]
                var successes = currentData["successes"]
                var errors = currentData["errors"]
                var scannedCerts = currentData["scanned_certs"]

                document.getElementById('status').innerHTML += `
                    <p>扫描进程ID：${key}</p>
                    <p>爬取状态: ${scanStatus}</p>
                    <p>爬取时间: ${scanTime} 秒</p>
                    <p>扫描的域名数: ${scannedDomains}</p>
                    <p>成功次数: ${successes}</p>
                    <p>错误次数: ${errors}</p>
                    <p>扫描的证书数: ${scannedCerts}</p>
                `;
            }
        }

        // 如果任务未完成，继续轮询
        if (scanStatus !== 'Completed') {
            setTimeout(checkStatus, 2000); // 1秒后再次检查状态
        }
    })
    .catch(error => {
        console.error('Error checking status:', error);
    });
}

// 初次加载页面时开始检查状态
document.addEventListener('DOMContentLoaded', checkStatus);

