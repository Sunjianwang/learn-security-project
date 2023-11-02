SET NAMES utf8mb4;
SET FOREIGN_KEY_CHECKS = 0;

-- ----------------------------
-- Table structure for mooc_permissions
-- ----------------------------
DROP TABLE IF EXISTS `mooc_permissions`;
CREATE TABLE `mooc_permissions` (
                                    `id` varchar(64) NOT NULL,
                                    `permission_name` varchar(255) NOT NULL,
                                    `display_name` varchar(255) NOT NULL,
                                    PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3;

-- ----------------------------
-- Records of mooc_permissions
-- ----------------------------
BEGIN;
INSERT INTO `mooc_permissions` (`id`, `permission_name`, `display_name`) VALUES ('1', 'USER_READ', '查询用户信息');
INSERT INTO `mooc_permissions` (`id`, `permission_name`, `display_name`) VALUES ('2', 'USER_CREATE', '新建用户');
INSERT INTO `mooc_permissions` (`id`, `permission_name`, `display_name`) VALUES ('3', 'USER_UPDATE', '编辑用户信息');
INSERT INTO `mooc_permissions` (`id`, `permission_name`, `display_name`) VALUES ('4', 'USER_ADMIN', '用户管理');
COMMIT;

-- ----------------------------
-- Table structure for mooc_roles
-- ----------------------------
DROP TABLE IF EXISTS `mooc_roles`;
CREATE TABLE `mooc_roles` (
                              `id` bigint NOT NULL AUTO_INCREMENT,
                              `role_name` varchar(50) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL,
                              `display_name` varchar(255) NOT NULL,
                              `built_in` bit(1) NOT NULL DEFAULT b'1',
                              PRIMARY KEY (`id`) USING BTREE,
                              UNIQUE KEY `uk_mooc_roles_role_name` (`role_name`) USING BTREE
) ENGINE=InnoDB AUTO_INCREMENT=4 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- ----------------------------
-- Records of mooc_roles
-- ----------------------------
BEGIN;
INSERT INTO `mooc_roles` (`id`, `role_name`, `display_name`, `built_in`) VALUES (1, 'ROLE_USER', '客户端用户', b'1');
INSERT INTO `mooc_roles` (`id`, `role_name`, `display_name`, `built_in`) VALUES (2, 'ROLE_ADMIN', '超级管理员', b'1');
INSERT INTO `mooc_roles` (`id`, `role_name`, `display_name`, `built_in`) VALUES (3, 'ROLE_STAFF', '管理后台用户', b'1');
COMMIT;

-- ----------------------------
-- Table structure for mooc_roles_permissions
-- ----------------------------
DROP TABLE IF EXISTS `mooc_roles_permissions`;
CREATE TABLE `mooc_roles_permissions` (
                                          `role_id` varchar(64) NOT NULL,
                                          `permission_id` varchar(64) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3;

-- ----------------------------
-- Records of mooc_roles_permissions
-- ----------------------------
BEGIN;
INSERT INTO `mooc_roles_permissions` (`role_id`, `permission_id`) VALUES ('1', '1');
INSERT INTO `mooc_roles_permissions` (`role_id`, `permission_id`) VALUES ('2', '1');
INSERT INTO `mooc_roles_permissions` (`role_id`, `permission_id`) VALUES ('2', '2');
INSERT INTO `mooc_roles_permissions` (`role_id`, `permission_id`) VALUES ('2', '3');
INSERT INTO `mooc_roles_permissions` (`role_id`, `permission_id`) VALUES ('2', '4');
COMMIT;

-- ----------------------------
-- Table structure for mooc_users
-- ----------------------------
DROP TABLE IF EXISTS `mooc_users`;
CREATE TABLE `mooc_users` (
                              `id` bigint NOT NULL AUTO_INCREMENT,
                              `account_non_expired` bit(1) NOT NULL,
                              `account_non_locked` bit(1) NOT NULL,
                              `credentials_non_expired` bit(1) NOT NULL,
                              `email` varchar(254) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL,
                              `enabled` bit(1) NOT NULL,
                              `mobile` varchar(11) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL,
                              `name` varchar(50) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL,
                              `password` varchar(80) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL,
                              `username` varchar(50) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL,
                              `using_mfa` bit(1) NOT NULL,
                              `mfa_key` varchar(255) NOT NULL,
                              PRIMARY KEY (`id`) USING BTREE,
                              UNIQUE KEY `uk_mooc_users_username` (`username`) USING BTREE,
                              UNIQUE KEY `uk_mooc_users_mobile` (`mobile`) USING BTREE,
                              UNIQUE KEY `uk_mooc_users_email` (`email`) USING BTREE
) ENGINE=InnoDB AUTO_INCREMENT=4 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- ----------------------------
-- Records of mooc_users
-- ----------------------------
BEGIN;
INSERT INTO `mooc_users` (`id`, `account_non_expired`, `account_non_locked`, `credentials_non_expired`, `email`, `enabled`, `mobile`, `name`, `password`, `username`, `using_mfa`, `mfa_key`) VALUES (1, b'1', b'1', b'1', 'zhangsan@local.dev', b'1', '13000000001', 'Zhang San', '{bcrypt}$2a$10$R7rQ1ODPMKWU2eQ221Oi9OpapeM5fDupaBQOucw0JjKUlottrvFEO', 'user', b'0', 'OTNkNDllMTctNzQ4NS00ZDEzLWJiNWUtNmYzYWVhNjM4YzVm');
INSERT INTO `mooc_users` (`id`, `account_non_expired`, `account_non_locked`, `credentials_non_expired`, `email`, `enabled`, `mobile`, `name`, `password`, `username`, `using_mfa`, `mfa_key`) VALUES (2, b'1', b'1', b'1', 'lisi@local.dev', b'1', '13000000002', 'Li Si', '{bcrypt}$2a$10$tntIFm7J2D3hQy4iv/z0He.AevXeusOMcMPqDdi.BVJHIR2zG.l4W', 'old_user', b'0', '');
COMMIT;

-- ----------------------------
-- Table structure for mooc_users_roles
-- ----------------------------
DROP TABLE IF EXISTS `mooc_users_roles`;
CREATE TABLE `mooc_users_roles` (
                                    `user_id` bigint NOT NULL,
                                    `role_id` bigint NOT NULL,
                                    PRIMARY KEY (`user_id`,`role_id`) USING BTREE,
                                    KEY `fk_users_roles_role_id_mooc_roles_id` (`role_id`) USING BTREE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- ----------------------------
-- Records of mooc_users_roles
-- ----------------------------
BEGIN;
INSERT INTO `mooc_users_roles` (`user_id`, `role_id`) VALUES (1, 1);
INSERT INTO `mooc_users_roles` (`user_id`, `role_id`) VALUES (2, 1);
INSERT INTO `mooc_users_roles` (`user_id`, `role_id`) VALUES (1, 2);
INSERT INTO `mooc_users_roles` (`user_id`, `role_id`) VALUES (1, 3);
COMMIT;

SET FOREIGN_KEY_CHECKS = 1;
