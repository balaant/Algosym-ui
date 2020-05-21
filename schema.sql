create table bhacklogins
(
	login varchar(40),
	password varchar(30),
	permit varchar default 'user'::character varying,
	reg_new_one integer default 1,
	create_new_files integer default 1
);

alter table bhacklogins owner to postgres;


INSERT INTO public.bhacklogins (login, password, permit, reg_new_one, create_new_files) VALUES ('test@test.com', '111', 'user', 1, 1);
INSERT INTO public.bhacklogins (login, password, permit, reg_new_one, create_new_files) VALUES ('a@b.com', '1', 'admin', 1, 1);