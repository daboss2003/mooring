-- Namespace catch-all routes (spec.edge.routes[].subdomain: "*"). A catch-all stores its hostname as
-- `*.<apex>` and matches every single-label name under the namespace apex that no more-specific route
-- claims. 0 = an ordinary route, so existing routes are unaffected. Requires dns01 + operator consent
-- (edge.base_domains[].catch_all / edge.catch_all) on the namespace, enforced at deploy.
ALTER TABLE app_routes ADD COLUMN catch_all INTEGER NOT NULL DEFAULT 0;
