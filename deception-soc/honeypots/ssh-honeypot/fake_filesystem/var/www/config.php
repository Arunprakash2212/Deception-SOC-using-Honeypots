<?php
// Application Configuration - FAKE HONEYPOT FILE
return [
    'database' => [
        'host'     => 'db-prod-01.internal.corp',
        'port'     => 3306,
        'name'     => 'production_db',
        'username' => 'app_rw',
        'password' => 'Pr0d_DB_FAKE_P@ssw0rd_2024!',
    ],
    'stripe' => [
        'secret_key' => 'sk_live_FAKE_4eC39HqLyjWDarjtT1zdp7dc',
        'public_key' => 'pk_live_FAKE_TYooMQauvdEDq54NiTphI7jx',
    ],
    'sendgrid' => [
        'api_key' => 'SG.FAKE_nW4Jd0RhR-OGY0olMEQ.FAKE_key_xyz',
    ],
    'app' => [
        'secret'         => 'FAKE_app_s3cret_key_dJ8kL2mN4pQ6r',
        'encryption_key' => 'FAKE_enc_k3y_aEs256_xB7yC9zD1eF3g',
        'jwt_secret'     => 'FAKE_jwt_secr3t_hS512_kM4nP6qR8s',
    ],
];
