
function getCertResult() {

    fetch('/cert/result')

    .then(response => {
        if (!response.ok) {
            throw new Error('Network response was not ok');
        }
        return response.json();
    })
    .then(data => {

        var cert_result = data["cert_result"]
        var error_result = data["error_result"]
        
        document.getElementById('certnum').innerHTML = `<p>${cert_result["num"]}</p>`
        document.getElementById('expired').innerHTML = `<p>${cert_result["expired"]}</p>`
        document.getElementById('avg_length').innerHTML = `<p>${cert_result["avg_length"]}</p>`
        document.getElementById('algo').innerHTML = ``
        
        for (var k in cert_result["algo_dict"]) {
            var currentData = cert_result["algo_dict"][k];
            var pElement = document.createElement('p');
            pElement.textContent = k;
            
            document.getElementById('algo').appendChild(pElement);
            document.getElementById('algo').innerHTML += `
                <p>${currentData}</p>
            `;
        }
    })
    .catch(error => {
        console.error('Error checking status:', error);
    });
}

// 初次加载页面时开始检查状态
document.addEventListener('DOMContentLoaded', getCertResult);
