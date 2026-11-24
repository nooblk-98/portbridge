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
                    // Only return to a known dashboard page, never an arbitrary URL.
                    const next = new URLSearchParams(window.location.search).get('next');
                    const pages = ['/', '/clients', '/routes', '/forwarding'];
                    window.location.href = pages.includes(next) ? next : '/';
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
