function getCertificate() {
    let domain = document.getElementById('domainInput').value;
    fetch('/get_certificate', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({domain: domain})
    })
    .then(response => response.json())
    .then(data => {
        let content = data.content.replace(/\"/g, ''); // 移除所有双引号
        let verified = data.verified;

        let certificateDiv = document.getElementById('certificateDetails');
        certificateDiv.innerHTML = content;
        certificateDiv.className = verified ? 'certificate verified' : 'certificate not-verified'; // 更新类名

        // 更新验证状态文字
        let statusDiv = document.getElementById('verificationStatus');
        statusDiv.innerHTML = verified ? 'TLS Verified' : 'TLS Not Verified';
        statusDiv.className = verified ? 'verified-text' : 'not-verified-text';
    });
}

function getCA() {
    let domain = document.getElementById('domainInput').value;
    fetch('/get_ca', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({domain: domain})
    })
    .then(response => response.json())
    .then(data => {
        let formattedData = JSON.stringify(data, null, 2);
        formattedData = formattedData.replace(/\"/g, ''); // 移除所有双引号
        document.getElementById('caDetails').innerHTML = formattedData;
    });
}

function handleKeyPressCertificate(event) {
    // 检查按下的键是否是回车键
    if (event.key === "Enter" || event.keyCode === 13) {
        // 阻止默认行为（例如防止表单提交）
        event.preventDefault();
        // 调用 getCertificate 函数
        getCertificate();
    }
}

function handleKeyPressCa(event) {
    // 检查按下的键是否是回车键
    if (event.key === "Enter" || event.keyCode === 13) {
        // 阻止默认行为（例如防止表单提交）
        event.preventDefault();
        // 调用 getCertificate 函数
        getCa();
    }
}

