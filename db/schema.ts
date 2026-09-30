import {sqliteTable,text,integer,index} from "drizzle-orm/sqlite-core";
export const investigations=sqliteTable('investigations',{
 id:text('id').primaryKey(),owner:text('owner').notNull(),report:text('report').notNull(),created:integer('created').notNull(),expires:integer('expires').notNull()
},t=>[index('idx_investigations_owner_created').on(t.owner,t.created),index('idx_investigations_expires').on(t.expires)]);
export const reviews=sqliteTable('reviews',{
 investigationId:text('investigation_id').primaryKey().references(()=>investigations.id,{onDelete:'cascade'}),verdict:text('verdict').notNull(),note:text('note').notNull(),at:text('at').notNull()
});
export const feedback=sqliteTable('feedback',{
 investigationId:text('investigation_id').primaryKey().references(()=>investigations.id,{onDelete:'cascade'}),category:text('category').notNull(),note:text('note').notNull(),at:text('at').notNull()
});
export const reviewEvents=sqliteTable('review_events',{
 id:text('id').primaryKey(),investigationId:text('investigation_id').notNull().references(()=>investigations.id,{onDelete:'cascade'}),action:text('action').notNull(),at:text('at').notNull()
},t=>[index('idx_review_events_investigation_at').on(t.investigationId,t.at)]);
export const rateBuckets=sqliteTable('rate_buckets',{
 key:text('key').primaryKey(),count:integer('count').notNull(),expires:integer('expires').notNull()
},t=>[index('idx_rate_buckets_expires').on(t.expires)]);
