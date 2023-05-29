create table issuer (
    issuer_id uuid not null primary key,
    name text not null,
    created_at timestamp not null default now()
);

create table revoked_block (
    revocation_id text not null primary key,
    issuer_id uuid not null references issuer(issuer_id),
    expires_at timestamp,
    revoked_at timestamp not null default now()
);

insert into issuer (issuer_id, name) values (
    '4d38053f-5de4-459b-8558-f194a1defca5', 'murtaugh'
);