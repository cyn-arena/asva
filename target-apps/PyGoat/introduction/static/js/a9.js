// console.log("imported a9.js");

event1 = function(){
    document.getElementById("a9_b1").style.display = 'none';
    document.getElementById("a9_d1").style.display = 'flex';
}

event2 = function(){
    document.getElementById("a9_b2").style.display = 'none';
    document.getElementById("a9_d2").style.display = 'flex';
}

event3 = function(){
    var log_code = document.getElementById('a9_log').value
    var target_code = document.getElementById('a9_api').value

    var csrfTokenInput = document.querySelector('input[name="csrfmiddlewaretoken"]');
    var csrfToken = csrfTokenInput ? csrfTokenInput.value : '';
    if (!csrfToken) {
        var csrfMatch = document.cookie.match(/(?:^|;\s*)csrftoken=([^;]+)/);
        csrfToken = csrfMatch ? decodeURIComponent(csrfMatch[1]) : '';
    }

    var formdata = new FormData();
    if (csrfToken) {
        formdata.append("csrfmiddlewaretoken", csrfToken);
    }
    formdata.append("log_code", log_code);
    formdata.append("api_code", target_code);

    var requestOptions = {
    method: 'POST',
    body: formdata,
    redirect: 'follow'
    };

    fetch("/2021/discussion/A9/api", requestOptions)
    .then(response => response.text())
    .then(result => {
        let data = JSON.parse(result);  // parse JSON string into object
        console.log(data.logs);
        document.getElementById("a9_d3").style.display = 'flex';
        for (var i = 0; i < data.logs.length; i++) {
            var li = document.createElement("li");
            li.innerHTML = data.logs[i];
            document.getElementById("a9_d3").appendChild(li);
        }
    })
    .catch(error => console.log('error', error));
    }