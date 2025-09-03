import React, { useState, useEffect, useCallback } from 'react';
import { Button, Col, Divider, Input, Modal, Row, Spin, Typography, message } from 'antd';;
import { 
  TwitterOutlined, 
  WechatOutlined, 
  WeiboOutlined, 
  FacebookOutlined, 
  LinkedinOutlined, 
  InstagramOutlined, 
  CopyOutlined,
  ShareAltOutlined,
  CheckOutlined
} from '@ant-design/icons';
import { useUIStore } from '../../stores/uiStore';
import { generateShareLink, createShareRecord } from '../../utils/api';

const { Text, Title } = Typography;
const { TextArea } = Input;

interface ShareModalProps {
  modalId: string;
  annotationId?: string;
  annotationTitle?: string;
  annotationDescription?: string;
  onClose?: () => void;
}

interface SharePlatform {
  key: string;
  name: string;
  icon: React.ReactNode;
  color: string;
  description: string;
}

const SHARE_PLATFORMS: SharePlatform[] = [
  {
    key: 'twitter',
    name: 'Twitter',
    icon: <TwitterOutlined />,
    color: '#1DA1F2',
    description: '分享到Twitter'
  },
  {
    key: 'wechat',
    name: '微信',
    icon: <WechatOutlined />,
    color: '#07C160',
    description: '分享到微信'
  },
  {
    key: 'weibo',
    name: '微博',
    icon: <WeiboOutlined />,
    color: '#E6162D',
    description: '分享到微博'
  },
  {
    key: 'facebook',
    name: 'Facebook',
    icon: <FacebookOutlined />,
    color: '#1877F2',
    description: '分享到Facebook'
  },
  {
    key: 'linkedin',
    name: 'LinkedIn',
    icon: <LinkedinOutlined />,
    color: '#0A66C2',
    description: '分享到LinkedIn'
  },
  {
    key: 'instagram',
    name: 'Instagram',
    icon: <InstagramOutlined />,
    color: '#E4405F',
    description: '分享到Instagram'
  }
];

const ShareModal: React.FC<ShareModalProps> = ({ 
  modalId, 
  annotationId, 
  annotationTitle = '有趣的臭味标注',
  annotationDescription,
  onClose 
}) => {
  const { closeModal } = useUIStore();
  const [shareData, setShareData] = useState<{
    shareUrl: string;
    shareText?: string;
    qrCode?: string;
    metadata?: Record<string, unknown>;
  } | null>(null);
  const [loading, setLoading] = useState(false);
  const [customMessage, setCustomMessage] = useState('');
  const [copiedLink, setCopiedLink] = useState(false);
  const [sharingPlatform, setSharingPlatform] = useState<string | null>(null);

  // 加载分享数据
  const loadShareData = useCallback(async () => {
    if (!annotationId) return;
    
    try {
      setLoading(true);
      const response = await generateShareLink(annotationId);
      setShareData(response.data);
      setCustomMessage(response.data.shareText || '');
    } catch (error) {
      console.error('加载分享数据失败:', error);
      message.error('加载分享数据失败');
    } finally {
      setLoading(false);
    }
  }, [annotationId]);

  useEffect(() => {
    if (annotationId) {
      loadShareData();
    }
  }, [annotationId, loadShareData]);

  // 复制链接
  const handleCopyLink = async () => {
    if (!shareData?.shareUrl) return;
    
    try {
      await navigator.clipboard.writeText(shareData.shareUrl);
      setCopiedLink(true);
      message.success('链接已复制到剪贴板');
      setTimeout(() => setCopiedLink(false), 2000);
    } catch (error) {
      console.error('复制失败:', error);
      message.error('复制失败，请手动复制');
    }
  };

  // 分享到平台
  const handleShare = async (platform: SharePlatform) => {
    if (!annotationId || !shareData) return;
    
    try {
      setSharingPlatform(platform.key);
      
      // 生成特定平台的分享链接
      const platformResponse = await generateShareLink(annotationId, platform.key);
      const shareUrl = platformResponse.data.shareUrl;
      
      // 记录分享行为
      await createShareRecord(annotationId, {
        platform: platform.key,
        shareUrl,
        shareData: {
          customMessage,
          platform: platform.key,
          timestamp: new Date().toISOString()
        }
      });
      
      // 打开分享窗口
      if (platform.key === 'wechat') {
        // 微信分享需要特殊处理
        message.info('请复制链接手动分享到微信');
        handleCopyLink();
      } else if (platform.key === 'instagram') {
        // Instagram分享需要特殊处理
        message.info('请复制链接手动分享到Instagram');
        handleCopyLink();
      } else {
        // 其他平台直接打开分享窗口
        const shareWindow = window.open(
          shareUrl,
          'share',
          'width=600,height=400,scrollbars=yes,resizable=yes'
        );
        
        if (!shareWindow) {
          message.warning('请允许弹窗以完成分享');
        } else {
          message.success(`正在分享到${platform.name}`);
        }
      }
    } catch (error) {
      console.error('分享失败:', error);
      message.error('分享失败，请稍后重试');
    } finally {
      setSharingPlatform(null);
    }
  };

  const handleClose = () => {
    if (onClose) {
      onClose();
    } else {
      closeModal(modalId);
    }
  };

  return (
    <Modal
      title={
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <ShareAltOutlined />
          <span>分享臭味标注</span>
        </div>
      }
      open={true}
      onCancel={handleClose}
      footer={null}
      width={600}
      bodyStyle={{ padding: '20px' }}
    >
      {loading ? (
        <div style={{ textAlign: 'center', padding: '40px 0' }}>
          <Spin size="large" />
          <div style={{ marginTop: 16 }}>加载分享数据中...</div>
        </div>
      ) : (
        <div>
          {/* 标注信息预览 */}
          {annotationId && (
            <div style={{ marginBottom: 20, padding: 16, background: '#f5f5f5', borderRadius: 8 }}>
              <Title level={5} style={{ margin: 0, marginBottom: 8 }}>
                {annotationTitle}
              </Title>
              {annotationDescription && (
                <Text type="secondary">{annotationDescription}</Text>
              )}
            </div>
          )}
          
          {/* 自定义分享文案 */}
          <div style={{ marginBottom: 20 }}>
            <Text strong>自定义分享文案：</Text>
            <TextArea
              value={customMessage}
              onChange={(e) => setCustomMessage(e.target.value)}
              placeholder="添加你的分享文案..."
              rows={3}
              maxLength={200}
              showCount
              style={{ marginTop: 8 }}
            />
          </div>
          
          {/* 分享链接 */}
          {shareData?.shareUrl && (
            <div style={{ marginBottom: 20 }}>
              <Text strong>分享链接：</Text>
              <div style={{ display: 'flex', gap: 8, marginTop: 8 }}>
                <Input
                  value={shareData.shareUrl}
                  readOnly
                  style={{ flex: 1 }}
                />
                <Button
                  icon={copiedLink ? <CheckOutlined /> : <CopyOutlined />}
                  onClick={handleCopyLink}
                  type={copiedLink ? 'primary' : 'default'}
                >
                  {copiedLink ? '已复制' : '复制'}
                </Button>
              </div>
            </div>
          )}
          
          <Divider>选择分享平台</Divider>
          
          {/* 分享平台按钮 */}
          <Row gutter={[16, 16]}>
            {SHARE_PLATFORMS.map((platform) => (
              <Col xs={12} sm={8} key={platform.key}>
                <Button
                  block
                  size="large"
                  icon={platform.icon}
                  loading={sharingPlatform === platform.key}
                  onClick={() => handleShare(platform)}
                  style={{
                    height: 60,
                    borderColor: platform.color,
                    color: platform.color,
                    display: 'flex',
                    flexDirection: 'column',
                    alignItems: 'center',
                    justifyContent: 'center',
                    gap: 4
                  }}
                  onMouseEnter={(e) => {
                    e.currentTarget.style.backgroundColor = platform.color;
                    e.currentTarget.style.color = 'white';
                  }}
                  onMouseLeave={(e) => {
                    e.currentTarget.style.backgroundColor = 'transparent';
                    e.currentTarget.style.color = platform.color;
                  }}
                >
                  <div style={{ fontSize: '18px' }}>{platform.icon}</div>
                  <div style={{ fontSize: '12px' }}>{platform.name}</div>
                </Button>
              </Col>
            ))}
          </Row>
          
          {/* 分享提示 */}
          <div style={{ marginTop: 20, padding: 12, background: '#f0f9ff', borderRadius: 6, border: '1px solid #bae7ff' }}>
            <Text type="secondary" style={{ fontSize: '12px' }}>
              💡 提示：分享后可以在个人中心查看分享历史和统计数据
            </Text>
          </div>
        </div>
      )}
    </Modal>
  );
};

export default ShareModal;