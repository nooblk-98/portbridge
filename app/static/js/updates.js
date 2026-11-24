// Looks for a newer PortBridge release on GitHub and remembers what the person
// decided about it. The browser makes the request (one small, public API call,
// cached for hours), so the server needs no outbound HTTPS client. Nothing about
// this installation is sent. Release notes come from outside the page, so they
// are rendered by building elements, never by assigning HTML.
(() => {
    const REPOSITORY = 'nooblk-98/portbridge';
    const RELEASE_API = `https://api.github.com/repos/${REPOSITORY}/releases/latest`;
    const RELEASE_PAGE_PREFIX = `https://github.com/${REPOSITORY}/`;

    const RELEASE_KEY = 'portbridge.update.release';
    const CHOICE_KEY = 'portbridge.update.choice';
    const CACHE_MS = 6 * 60 * 60 * 1000;
    const SNOOZE_MS = 24 * 60 * 60 * 1000;
    const REQUEST_TIMEOUT_MS = 8000;

    /** The commands from the README, so people can upgrade by hand. */
    const COMMANDS = {
        install: 'curl -fsSL https://raw.githubusercontent.com/nooblk-98/portbridge/main/install.sh | sudo bash -s -- --upgrade',
        docker: 'docker compose -f docker-compose-live.yml pull && docker compose -f docker-compose-live.yml up -d',
    };

    // ---- versions ---------------------------------------------------------

    /** `v1.4.2` or `1.4.2` as [1, 4, 2]; null when it is not a release number. */
    function parseVersion(text) {
        const match = /^v?(\d+)\.(\d+)\.(\d+)/.exec(String(text || '').trim());
        return match ? [Number(match[1]), Number(match[2]), Number(match[3])] : null;
    }

    /** -1, 0 or 1 like a sort comparator; 0 when either is not a release number. */
    function compareVersions(a, b) {
        const left = parseVersion(a);
        const right = parseVersion(b);
        if (!left || !right) return 0;
        for (let index = 0; index < 3; index += 1) {
            if (left[index] !== right[index]) return left[index] < right[index] ? -1 : 1;
        }
        return 0;
    }

    const isNewer = (latest, current) => compareVersions(latest, current) > 0;

    // ---- remembered state -------------------------------------------------

    function read(key) {
        try {
            const value = JSON.parse(localStorage.getItem(key));
            return value && typeof value === 'object' ? value : null;
        } catch {
            return null;
        }
    }

    function write(key, value) {
        try {
            localStorage.setItem(key, JSON.stringify(value));
        } catch {
            // Site data is blocked: the choice still applies until the page reloads.
        }
    }

    /** What was decided: `ignored` is a version, `remindAt` a time in ms. */
    const readChoice = () => read(CHOICE_KEY) || {};

    /** Hide this release's notice for a day. */
    function remindLater(now = Date.now()) {
        const choice = readChoice();
        write(CHOICE_KEY, { ...choice, remindAt: now + SNOOZE_MS });
    }

    /** Hide the notice until a newer release than `version` appears. */
    function ignore(version) {
        write(CHOICE_KEY, { ignored: version });
    }

    /** Whether to tell the person about `release`, given what they decided before. */
    function shouldNotify(release, current, choice = readChoice(), now = Date.now()) {
        if (!release || !isNewer(release.version, current)) return false;
        if (choice.ignored && compareVersions(choice.ignored, release.version) >= 0) return false;
        if (Number(choice.remindAt) > now) return false;
        return true;
    }

    // ---- the latest release -----------------------------------------------

    /** Keep only what the popup needs, and only from a plausible release. */
    function readRelease(data) {
        if (!data || typeof data.tag_name !== 'string' || !parseVersion(data.tag_name)) return null;
        const page = typeof data.html_url === 'string' && data.html_url.startsWith(RELEASE_PAGE_PREFIX)
            ? data.html_url
            : `${RELEASE_PAGE_PREFIX}releases`;
        return {
            version: data.tag_name.replace(/^v/, ''),
            url: page,
            notes: typeof data.body === 'string' ? data.body : '',
            publishedAt: typeof data.published_at === 'string' ? data.published_at : '',
        };
    }

    /** A release object in the shape `readRelease` produces, e.g. read back from the cache. */
    function isRelease(value) {
        return Boolean(value)
            && typeof value.version === 'string' && parseVersion(value.version) !== null
            && typeof value.url === 'string' && value.url.startsWith(RELEASE_PAGE_PREFIX)
            && typeof value.notes === 'string';
    }

    /**
     * The newest release, from the cache when it is fresh. Returns the cached
     * copy, however old, when GitHub cannot be reached, and null with none.
     */
    async function latestRelease({ fetchImpl = window.fetch.bind(window), now = Date.now() } = {}) {
        const cached = read(RELEASE_KEY);
        const release = isRelease(cached?.release) ? cached.release : null;
        if (release && now - Number(cached.fetchedAt) < CACHE_MS) return release;

        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
        try {
            const response = await fetchImpl(RELEASE_API, {
                headers: { Accept: 'application/vnd.github+json' },
                signal: controller.signal,
                credentials: 'omit',
                referrerPolicy: 'no-referrer',
            });
            if (!response.ok) return release;
            const fresh = readRelease(await response.json());
            if (!fresh) return release;
            write(RELEASE_KEY, { fetchedAt: now, release: fresh });
            return fresh;
        } catch {
            return release;
        } finally {
            clearTimeout(timer);
        }
    }

    // ---- release notes ----------------------------------------------------

    const STYLE = {
        heading: 'mb-1.5 mt-4 text-sm font-bold text-slate-900 first:mt-0 dark:text-white',
        paragraph: 'my-2 text-sm leading-relaxed text-slate-700 dark:text-slate-300',
        list: 'my-2 list-disc space-y-1.5 pl-5 text-sm leading-relaxed text-slate-700 dark:text-slate-300',
        code: 'rounded bg-slate-100 px-1 py-0.5 font-mono text-[0.8125rem] text-slate-800 dark:bg-slate-800 dark:text-slate-200',
        block: 'my-2 overflow-x-auto rounded-lg bg-slate-100 p-3 font-mono text-[0.8125rem] leading-relaxed text-slate-800 dark:bg-slate-900 dark:text-slate-200',
        link: 'text-primary-600 underline underline-offset-2 hover:text-primary-700 dark:text-primary-400',
        strong: 'font-semibold text-slate-900 dark:text-white',
    };

    const element = (tag, className, text) => {
        const node = document.createElement(tag);
        if (className) node.className = className;
        if (text !== undefined) node.textContent = text;
        return node;
    };

    /** Inline **bold**, `code` and [links](https://...) as DOM nodes. */
    function appendInline(parent, text) {
        const pattern = /\*\*([^*]+)\*\*|`([^`]+)`|\[([^\]]+)\]\((https?:\/\/[^\s)]+)\)|(https?:\/\/[^\s)]+)/g;
        let last = 0;
        for (const match of text.matchAll(pattern)) {
            if (match.index > last) parent.append(text.slice(last, match.index));
            if (match[1] !== undefined) {
                parent.append(element('strong', STYLE.strong, match[1]));
            } else if (match[2] !== undefined) {
                parent.append(element('code', STYLE.code, match[2]));
            } else {
                const link = element('a', STYLE.link, match[3] ?? match[5]);
                link.href = match[4] ?? match[5];
                link.target = '_blank';
                link.rel = 'noopener noreferrer';
                parent.append(link);
            }
            last = match.index + match[0].length;
        }
        if (last < text.length) parent.append(text.slice(last));
    }

    /**
     * Release notes (a small subset of Markdown) as a fragment: headings, lists,
     * paragraphs, code blocks, bold, code and links. The "Install or upgrade"
     * section (its heading and command block) is left out because the popup shows
     * those commands itself.
     */
    function renderNotes(markdown) {
        const fragment = document.createDocumentFragment();
        const lines = String(markdown || '').replace(/\r\n?/g, '\n').split('\n');
        let list = null;
        let paragraph = null;
        let skipping = false;

        const endBlocks = () => { list = null; paragraph = null; };

        for (let index = 0; index < lines.length; index += 1) {
            const line = lines[index];
            const heading = /^#{1,6}\s+(.*?)\s*#*\s*$/.exec(line);

            if (/^```/.test(line.trim())) {
                const body = [];
                for (index += 1; index < lines.length && !/^```/.test(lines[index].trim()); index += 1) {
                    body.push(lines[index]);
                }
                if (!skipping) fragment.append(element('pre', STYLE.block, body.join('\n')));
                // The install section is a heading and its command block; what follows is kept.
                skipping = false;
                endBlocks();
                continue;
            }
            if (heading) {
                endBlocks();
                skipping = /install or upgrade/i.test(heading[1]);
                if (!skipping) {
                    const title = element('h4', STYLE.heading);
                    appendInline(title, heading[1]);
                    fragment.append(title);
                }
                continue;
            }
            if (skipping) continue;

            const item = /^\s*[-*]\s+(.*)$/.exec(line);
            if (item) {
                paragraph = null;
                if (!list) {
                    list = element('ul', STYLE.list);
                    fragment.append(list);
                }
                const entry = element('li');
                appendInline(entry, item[1]);
                list.append(entry);
            } else if (line.trim() === '') {
                endBlocks();
            } else if (list && /^\s+\S/.test(line)) {
                // A wrapped list item continues on the indented line.
                list.lastElementChild.append(' ');
                appendInline(list.lastElementChild, line.trim());
            } else {
                list = null;
                if (!paragraph) {
                    paragraph = element('p', STYLE.paragraph);
                    fragment.append(paragraph);
                } else {
                    paragraph.append(' ');
                }
                appendInline(paragraph, line.trim());
            }
        }
        return fragment;
    }

    const api = {
        COMMANDS,
        parseVersion,
        compareVersions,
        isNewer,
        shouldNotify,
        remindLater,
        ignore,
        latestRelease,
        renderNotes,
    };
    if (typeof window !== 'undefined') window.PortBridgeUpdates = api;
    // Lets `node --test` load the pure functions without a browser.
    if (typeof module !== 'undefined') module.exports = api;
})();
