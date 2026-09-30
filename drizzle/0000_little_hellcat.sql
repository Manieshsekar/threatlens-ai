CREATE TABLE `feedback` (
	`investigation_id` text PRIMARY KEY NOT NULL,
	`category` text NOT NULL,
	`note` text NOT NULL,
	`at` text NOT NULL,
	FOREIGN KEY (`investigation_id`) REFERENCES `investigations`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE TABLE `investigations` (
	`id` text PRIMARY KEY NOT NULL,
	`owner` text NOT NULL,
	`report` text NOT NULL,
	`created` integer NOT NULL,
	`expires` integer NOT NULL
);
--> statement-breakpoint
CREATE INDEX `idx_investigations_owner_created` ON `investigations` (`owner`,`created`);--> statement-breakpoint
CREATE INDEX `idx_investigations_expires` ON `investigations` (`expires`);--> statement-breakpoint
CREATE TABLE `rate_buckets` (
	`key` text PRIMARY KEY NOT NULL,
	`count` integer NOT NULL,
	`expires` integer NOT NULL
);
--> statement-breakpoint
CREATE INDEX `idx_rate_buckets_expires` ON `rate_buckets` (`expires`);--> statement-breakpoint
CREATE TABLE `review_events` (
	`id` text PRIMARY KEY NOT NULL,
	`investigation_id` text NOT NULL,
	`action` text NOT NULL,
	`at` text NOT NULL,
	FOREIGN KEY (`investigation_id`) REFERENCES `investigations`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE INDEX `idx_review_events_investigation_at` ON `review_events` (`investigation_id`,`at`);--> statement-breakpoint
CREATE TABLE `reviews` (
	`investigation_id` text PRIMARY KEY NOT NULL,
	`verdict` text NOT NULL,
	`note` text NOT NULL,
	`at` text NOT NULL,
	FOREIGN KEY (`investigation_id`) REFERENCES `investigations`(`id`) ON UPDATE no action ON DELETE cascade
);
