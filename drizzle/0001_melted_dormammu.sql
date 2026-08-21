CREATE TABLE `sentinel_audit_events` (
	`id` varchar(32) NOT NULL,
	`userId` int NOT NULL,
	`eventKind` enum('CHECK_IN','STATE_TRANSITION','CONFIG_UPDATED','PANIC_WIPE','VAULT_CREATED','VAULT_DELETED') NOT NULL,
	`fromState` varchar(16),
	`toState` varchar(16),
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `sentinel_audit_events_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `sentinel_profiles` (
	`id` int AUTO_INCREMENT NOT NULL,
	`userId` int NOT NULL,
	`state` enum('ARMED','ALERT','CRITICAL','TRIGGERED') NOT NULL DEFAULT 'ARMED',
	`checkInIntervalMinutes` int NOT NULL DEFAULT 1440,
	`alertGraceMinutes` int NOT NULL DEFAULT 120,
	`criticalGraceMinutes` int NOT NULL DEFAULT 120,
	`lastCheckInAt` timestamp NOT NULL DEFAULT (now()),
	`stateChangedAt` timestamp NOT NULL DEFAULT (now()),
	`scheduleCronTaskUid` varchar(65),
	`scheduleNextExecutionAt` timestamp,
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	`updatedAt` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP,
	CONSTRAINT `sentinel_profiles_id` PRIMARY KEY(`id`),
	CONSTRAINT `sentinel_profiles_user_unique` UNIQUE(`userId`)
);
--> statement-breakpoint
CREATE TABLE `sentinel_trigger_events` (
	`id` varchar(32) NOT NULL,
	`userId` int NOT NULL,
	`channel` enum('SECURE_WEBHOOK','AUTOMATED_EMAIL','MESH_PING') NOT NULL,
	`escalationState` enum('ARMED','ALERT','CRITICAL','TRIGGERED') NOT NULL,
	`status` varchar(32) NOT NULL DEFAULT 'SIMULATED_DISPATCHED',
	`dispatchedAt` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `sentinel_trigger_events_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `vault_entries` (
	`id` varchar(32) NOT NULL,
	`userId` int NOT NULL,
	`ciphertext` longtext NOT NULL,
	`iv` varchar(128) NOT NULL,
	`encryptionVersion` varchar(32) NOT NULL DEFAULT 'AES-GCM-256/v1',
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `vault_entries_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
ALTER TABLE `sentinel_audit_events` ADD CONSTRAINT `sentinel_audit_events_userId_users_id_fk` FOREIGN KEY (`userId`) REFERENCES `users`(`id`) ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE `sentinel_profiles` ADD CONSTRAINT `sentinel_profiles_userId_users_id_fk` FOREIGN KEY (`userId`) REFERENCES `users`(`id`) ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE `sentinel_trigger_events` ADD CONSTRAINT `sentinel_trigger_events_userId_users_id_fk` FOREIGN KEY (`userId`) REFERENCES `users`(`id`) ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE `vault_entries` ADD CONSTRAINT `vault_entries_userId_users_id_fk` FOREIGN KEY (`userId`) REFERENCES `users`(`id`) ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE INDEX `sentinel_audit_owner_time_idx` ON `sentinel_audit_events` (`userId`,`createdAt`);--> statement-breakpoint
CREATE INDEX `sentinel_profiles_schedule_idx` ON `sentinel_profiles` (`scheduleCronTaskUid`);--> statement-breakpoint
CREATE INDEX `sentinel_trigger_owner_time_idx` ON `sentinel_trigger_events` (`userId`,`dispatchedAt`);--> statement-breakpoint
CREATE INDEX `vault_entries_owner_idx` ON `vault_entries` (`userId`);