import { Button, Col, Input, Popover, Row, Space, message } from 'antd';;

import React, { useState } from 'react';

import { SmileOutlined, SendOutlined } from '@ant-design/icons';
import { createComment, updateComment } from '../../utils/api';

const { TextArea } = Input;

// 常用表情包
const EMOJI_LIST = [
  '😀', '😃', '😄', '😁', '😆', '😅', '🤣', '😂',
  '🙂', '🙃', '😉', '😊', '😇', '🥰', '😍', '🤩',
  '😘', '😗', '😚', '😙', '😋', '😛', '😜', '🤪',
  '😝', '🤑', '🤗', '🤭', '🤫', '🤔', '🤐', '🤨',
  '😐', '😑', '😶', '😏', '😒', '🙄', '😬', '🤥',
  '😔', '😕', '🙁', '😖', '😣', '😞', '😓', '😩',
  '😫', '🥱', '😴', '😪', '😵', '🤯', '🤠', '🥳',
  '😎', '🤓', '🧐', '😤', '😠', '😡', '🤬', '😱',
  '😨', '😰', '😥', '😢', '😭', '😳', '🤪', '😵‍💫'
];

// 搞笑文本表情
const FUNNY_EMOJIS = [
  '(╯°□°）╯︵ ┻━┻', '¯\\_(ツ)_/¯', '(ಠ_ಠ)', '(͡° ͜ʖ ͡°)',
  '(╭☞•́⍛•̀)╭☞', '(☞ﾟヮﾟ)☞', '┬─┬ノ( º _ ºノ)', '(ง •̀_•́)ง',
  '(づ｡◕‿‿◕｡)づ', '(つ◕_◕)つ', '(╯︵╰)', '(◕‿◕)',
  '(⌐■_■)', '(ಥ﹏ಥ)', '(ʘ‿ʘ)', '(｡◕‿◕｡)',
  '(╯°Д°）╯︵ /(.□ . \\)', '(ﾉ◕ヮ◕)ﾉ*:･ﾟ✧', '(☆▽☆)', '(≧∇≦)/',
];

interface CommentEditorProps {
  annotationId: string;
  parentId?: string;
  commentId?: string; // 用于编辑现有评论
  initialContent?: string;
  placeholder?: string;
  onSuccess?: () => void;
  onCancel?: () => void;
}

const CommentEditor: React.FC<CommentEditorProps> = ({
  annotationId,
  parentId,
  commentId,
  initialContent = '',
  placeholder = '写下你的搞笑评论...',
  onSuccess,
  onCancel
}) => {
  const [content, setContent] = useState(initialContent);
  const [loading, setLoading] = useState(false);
  const [emojiVisible, setEmojiVisible] = useState(false);

  // 提交评论
  const handleSubmit = async () => {
    if (!content.trim()) {
      message.warning('评论内容不能为空');
      return;
    }

    if (content.length > 500) {
      message.warning('评论内容不能超过500字符');
      return;
    }

    try {
      setLoading(true);
      
      if (commentId) {
        // 编辑现有评论
        await updateComment(commentId, { content });
        message.success('评论更新成功');
      } else {
        // 创建新评论
        await createComment(annotationId, { content, parentId });
        message.success(parentId ? '回复成功' : '评论成功');
      }
      
      setContent('');
      onSuccess?.();
    } catch (error: unknown) {
      console.error('评论操作失败:', error);
      const errorMessage = error instanceof Error && 'response' in error && 
        typeof error.response === 'object' && error.response !== null &&
        'data' in error.response && typeof error.response.data === 'object' &&
        error.response.data !== null && 'error' in error.response.data &&
        typeof error.response.data.error === 'string'
        ? error.response.data.error
        : '操作失败';
      
      message.error(errorMessage);
    } finally {
      setLoading(false);
    }
  };

  // 插入表情
  const insertEmoji = (emoji: string) => {
    const textarea = document.querySelector('.comment-textarea') as HTMLTextAreaElement;
    if (textarea) {
      const start = textarea.selectionStart;
      const end = textarea.selectionEnd;
      const newContent = content.substring(0, start) + emoji + content.substring(end);
      setContent(newContent);
      
      // 设置光标位置
      setTimeout(() => {
        textarea.focus();
        textarea.setSelectionRange(start + emoji.length, start + emoji.length);
      }, 0);
    } else {
      setContent(prev => prev + emoji);
    }
    setEmojiVisible(false);
  };

  // 表情选择器内容
  const emojiContent = (
    <div style={{ width: 300, maxHeight: 200, overflow: 'auto' }}>
      <div style={{ marginBottom: 12 }}>
        <div style={{ fontWeight: 'bold', marginBottom: 8 }}>常用表情</div>
        <Row gutter={[4, 4]}>
          {EMOJI_LIST.map((emoji, index) => (
            <Col key={`item-${index}`}>
              <Button
                type="text"
                size="small"
                style={{ padding: '4px 8px', fontSize: '16px' }}
                onClick={() => insertEmoji(emoji)}
              >
                {emoji}
              </Button>
            </Col>
          ))}
        </Row>
      </div>
      
      <div>
        <div style={{ fontWeight: 'bold', marginBottom: 8 }}>搞笑表情</div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
          {FUNNY_EMOJIS.map((emoji, index) => (
            <Button
              key={`item-${index}`}
              type="text"
              size="small"
              style={{ 
                textAlign: 'left', 
                height: 'auto', 
                padding: '4px 8px',
                fontSize: '12px',
                fontFamily: 'monospace'
              }}
              onClick={() => insertEmoji(emoji)}
            >
              {emoji}
            </Button>
          ))}
        </div>
      </div>
    </div>
  );

  return (
    <div>
      <TextArea
        className="comment-textarea"
        value={content}
        onChange={(e: React.ChangeEvent<HTMLTextAreaElement>) => setContent(e.target.value)}
        placeholder={placeholder}
        rows={3}
        maxLength={500}
        showCount
        style={{ marginBottom: 8 }}
      />
      
      <Space>
        <Popover
          content={emojiContent}
          title="选择表情"
          trigger="click"
          open={emojiVisible}
          onOpenChange={setEmojiVisible}
          placement="topLeft"
        >
          <Button
            type="text"
            icon={<SmileOutlined />}
            size="small"
          >
            表情
          </Button>
        </Popover>
        
        <div style={{ flex: 1 }} />
        
        {onCancel && (
          <Button size="small" onClick={onCancel}>
            取消
          </Button>
        )}
        
        <Button
          type="primary"
          size="small"
          icon={<SendOutlined />}
          loading={loading}
          onClick={handleSubmit}
          disabled={!content.trim()}
        >
          {commentId ? '更新' : (parentId ? '回复' : '发布')}
        </Button>
      </Space>
    </div>
  );
};

export default CommentEditor;