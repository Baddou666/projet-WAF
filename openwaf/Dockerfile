FROM owasp/modsecurity-crs:nginx-alpine

COPY nginx.conf /etc/nginx/nginx.conf
COPY modsecurity.conf /etc/modsecurity.d/modsecurity.conf
COPY crs-setup.conf /etc/modsecurity.d/owasp-crs/crs-setup.conf
COPY rules/custom-exclusions.conf /etc/modsecurity.d/owasp-crs/rules/custom-exclusions.conf
