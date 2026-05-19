const element = document.getElementById("qrcode");
const qr = new QRCode(element, {
    text: element.getAttribute("data-qr"),
    width: 256,
    height: 256,
    colorDark: "#000000",
    colorLight: "#ffffff",
    correctLevel: QRCode.CorrectLevel.H
});