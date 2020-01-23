

    document.addEventListener('DOMContentLoaded', () => {

    const certification = document.getElementById('certification');
    console.log(certification.innerHTML);
    document.cookie = certification.innerHTML;
});