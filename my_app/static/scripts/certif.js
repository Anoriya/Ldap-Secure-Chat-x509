

    document.addEventListener('DOMContentLoaded', () => {
    var pki = forge.pki;
    var private_key;
    var keys;
    function createCertifRequest() {


        let certificationRequest = pki.createCertificationRequest();
        console.log(certificationRequest);
        certificationRequest.publicKey = keys.publicKey;

        var attrs = [{
            name: 'commonName',
            value: 'insat.org'
        }, {
            name: 'countryName',
            value: 'TN'
        }, {
            shortName: 'ST',
            value: 'Tunis'
        }, {
            name: 'localityName',
            value: 'Blacksburg'
        }, {
            name: 'organizationName',
            value: 'Test'
        }, {
            shortName: 'OU',
            value: 'Test'
        }];
        certificationRequest.setSubject(attrs);
        certificationRequest.sign(keys.privateKey);

        let certificationRequestToPem = pki.certificationRequestToPem(certificationRequest);
        console.log(certificationRequestToPem);
        return certificationRequestToPem;
    }

        function download(filename, text) {
            var element = document.createElement('a');
            element.setAttribute('href', 'data:text/plain;charset=utf-8,' + encodeURIComponent(text));
            element.setAttribute('download', filename);

            element.style.display = 'none';
            document.body.appendChild(element);

            element.click();

            document.body.removeChild(element);
        }

    document.getElementById('register').onclick = () => {
        const req = createCertifRequest();
        const form = document.getElementById('form');
        form.elements["request"].value =req;
        console.log(form.elements["request"].value)
        form.submit();

    };



    document.getElementById('download').onclick = () => {
        console.log('in download')
        keys = pki.rsa.generateKeyPair(2048);
        const publicKeyPem = forge.pki.publicKeyToPem(keys.publicKey);
        const privateKeyPem = forge.pki.privateKeyToPem(keys.privateKey);
        window.localStorage.setItem("private_key", privateKeyPem);
        download("private_key.txt", privateKeyPem)
        download("public_key.txt",publicKeyPem)
    }
});