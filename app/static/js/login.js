function loginApp() {
    return {
        password: '',
        error: '',
        loading: false,
        async login() {
            this.loading = true;
            this.error = '';
            try {
                const res = await fetch('/auth/login', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ password: this.password })
                });
                const data = await res.json();
                if (res.ok) {
                    window.location.href = '/';
                } else {
                    this.error = data.error || 'Login failed';
                }
            } catch (e) {
                this.error = 'Connection error';
            } finally {
                this.loading = false;
            }
        }
    }
}

// Dark mode check
if (localStorage.getItem('theme') === 'dark' || (!('theme' in localStorage) && window.matchMedia('(prefers-color-scheme: dark)').matches)) {
    document.documentElement.classList.add('dark');
} else {
    document.documentElement.classList.remove('dark');
}
