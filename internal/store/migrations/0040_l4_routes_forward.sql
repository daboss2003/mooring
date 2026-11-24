-- How an L4 route is forwarded (spec.edge.l4_routes[].forward): '' or 'proxy' = the
-- nginx stream LB; 'kernel' = Docker publishes the port on the service and nginx renders
-- nothing for it. '' keeps existing routes on the LB.
ALTER TABLE app_l4_routes ADD COLUMN forward TEXT NOT NULL DEFAULT '';
