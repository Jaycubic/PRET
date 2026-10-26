-- DESTRUCTIVE: drops the application schema objects and all data in them.
-- All objects are explicitly qualified under the public schema.

DROP FUNCTION public.purge_expired_history();
DROP TABLE public.credentials;
DROP TABLE public.settings;
DROP TABLE public.audit_log;
DROP TABLE public.results;
DROP TABLE public.jobs;
DROP TABLE public.authorized_networks;
DROP TABLE public.device_services;
DROP TABLE public.devices;
DROP TABLE public.app_users;
