
// import logger from './logger.js';

function startScanning() {
    // 禁用按钮
    document.getElementById('scanButton').disabled = true;

    // 向后端发送开始扫描的请求
    console.log('Before fetch request');
    // logger.info('Sending scan request to backend...')
    fetch('/system/scan', {
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
        // 跳转到新页面，并将任务ID传递给新页面

        window.location.href = '/system/scan_status';
        
    })
    .catch(error => {
        // logger.error('Error starting scan:', error);
        console.error('Error starting scan:', error);
        
        // 发生错误时启用按钮
        document.getElementById('scanButton').disabled = false;
    });
}

