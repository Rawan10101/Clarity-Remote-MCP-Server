document.addEventListener("DOMContentLoaded", () => {
  const loginForm = document.getElementById("login-form");
  const errorMsg = document.getElementById("error-msg");

  if (loginForm) {
    loginForm.addEventListener("submit", (e) => {
      const username = loginForm.username.value;
      const password = loginForm.password.value;

      if (!username || !password) {
        e.preventDefault();
        errorMsg.classList.remove("hidden");
        errorMsg.textContent = "Please enter valid credentials.";
      }
    });
  }
});
