import React, { useState } from 'react';
import { Badge, Modal, Tabs } from 'antd';
import { MessageCircle, Heart, Flame } from 'lucide-react';
import CommentList from './CommentList';

interface CommentModalProps {
  visible: boolean;
  onClose: () => void;
  annotationId: string;
  annotationTitle?: string;
  commentsCount?: number;
}

const CommentModal: React.FC<CommentModalProps> = ({
  visible,
  onClose,
  annotationId,
  annotationTitle = '臭味标注',
  commentsCount = 0
}) => {
  const [activeTab, setActiveTab] = useState('comments');
  const [localCommentsCount, setLocalCommentsCount] = useState(commentsCount);

  // 评论创建成功回调
  const handleCommentCreate = () => {
    setLocalCommentsCount(prev => prev + 1);
  };

  const tabItems = [
    {
      key: 'comments',
      label: (
        <span>
          <MessageCircle size={16} />
          <span style={{ marginLeft: 4 }}>评论</span>
          {localCommentsCount > 0 && (
            <Badge 
              count={localCommentsCount} 
              size="small" 
              style={{ marginLeft: 4 }}
            />
          )}
        </span>
      ),
      children: (
        <CommentList 
          annotationId={annotationId}
          onCommentCreate={handleCommentCreate}
        />
      )
    },
    {
      key: 'hot',
      label: (
        <span>
          <Flame size={16} />
          <span style={{ marginLeft: 4 }}>热门</span>
        </span>
      ),
      children: (
        <div style={{ textAlign: 'center', padding: '40px 0', color: '#999' }}>
          热门评论功能开发中...
        </div>
      )
    },
    {
      key: 'liked',
      label: (
        <span>
          <Heart size={16} />
          <span style={{ marginLeft: 4 }}>我赞过的</span>
        </span>
      ),
      children: (
        <div style={{ textAlign: 'center', padding: '40px 0', color: '#999' }}>
          我赞过的评论功能开发中...
        </div>
      )
    }
  ];

  return (
    <Modal
      title={
        <div>
          <MessageCircle style={{ marginRight: 8 }} size={20} />
          {annotationTitle} - 评论区
        </div>
      }
      open={visible}
      onCancel={onClose}
      footer={null}
      width={800}
      style={{ top: 20 }}
      bodyStyle={{ 
        maxHeight: 'calc(100vh - 200px)', 
        overflow: 'auto',
        padding: '16px 24px'
      }}
    >
      <Tabs
        activeKey={activeTab}
        onChange={setActiveTab}
        items={tabItems}
        size="small"
      />
    </Modal>
  );
};

export default CommentModal;