-- 修改 lbs_rewards 表，使 annotation_id 字段可选
-- 这样用户可以在没有特定标注的情况下进行签到

ALTER TABLE lbs_rewards 
ALTER COLUMN annotation_id DROP NOT NULL;

-- 更新外键约束，允许 annotation_id 为 NULL 时不进行外键检查
ALTER TABLE lbs_rewards 
DROP CONSTRAINT IF EXISTS lbs_rewards_annotation_id_fkey;

ALTER TABLE lbs_rewards 
ADD CONSTRAINT lbs_rewards_annotation_id_fkey 
FOREIGN KEY (annotation_id) 
REFERENCES annotations(id) 
ON DELETE SET NULL;