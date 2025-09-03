import React, { useState, useEffect } from 'react';
import { Button, Card, Col, Form, Input, Modal, Row, Slider, Tag, Upload, message, Typography } from 'antd';
import type { UploadFile } from 'antd';
import { 
  MapPin,
  Smile,
  Camera
} from 'lucide-react';
import { useUIStore } from '../../stores/uiStore';
import { useAuthStore } from '../../stores/authStore';
import api from '../../utils/api';

const { Text } = Typography;
const { TextArea } = Input;

interface PrankFormData {
  latitude?: number;
  longitude?: number;
  smell_intensity: number;
  description: string;
  media_files?: string[];
}

interface PrankCreateModalProps {
  modalId: string;
}

const PrankCreateModal: React.FC<PrankCreateModalProps> = () => {
  const { modals, closeModal, addNotification } = useUIStore();
  const { user } = useAuthStore();
  const [form] = Form.useForm();
  const [loading, setLoading] = useState(false);
  const [fileList, setFileList] = useState<UploadFile[]>([]);
  
  const isOpen = modals.some(modal => modal.type === 'prank-create');
  const modalData = modals.find(modal => modal.type === 'prank-create');

  useEffect(() => {
    if (isOpen && modalData) {
      form.setFieldsValue({
        latitude: 39.9042, // 默认位置
        longitude: 116.4074,
        smell_intensity: 5,
        description: ''
      });
    }
  }, [isOpen, modalData, form]);

  const handleClose = () => {
    form.resetFields();
    setFileList([]);
    closeModal('prank-create');
  };

  const handleSubmit = async (values: PrankFormData) => {
    if (!user) {
      message.error('请先登录');
      return;
    }

    try {
      setLoading(true);
      
      const formData = {
        latitude: values.latitude || 39.9042,
        longitude: values.longitude || 116.4074,
        smell_intensity: values.smell_intensity,
        description: values.description,
        media_files: fileList
          .filter(file => file.status === 'done' && file.response?.success)
          .map(file => (file.response as { success: boolean; data?: { files?: Array<{ id: string }> } })?.data?.files?.[0]?.id)
          .filter(Boolean)
      };

      await api.post('/annotations', formData);
      
      addNotification({
          type: 'success',
          title: '创建成功',
          message: '恶搞标注已创建成功！'
        });
      
      handleClose();
      
      // 刷新页面数据
      window.location.reload();
      
    } catch (error: unknown) {
      console.error('创建标注失败:', error);
      const errorMessage = error instanceof Error && 'response' in error && 
        typeof error.response === 'object' && error.response !== null &&
        'data' in error.response && typeof error.response.data === 'object' &&
        error.response.data !== null && 'message' in error.response.data &&
        typeof error.response.data.message === 'string'
        ? error.response.data.message
        : '创建恶搞标注失败，请重试';
      
      addNotification({
          type: 'error',
          title: '创建失败',
          message: errorMessage
        });
    } finally {
      setLoading(false);
    }
  };

  const getIntensityLabel = (value: number) => {
    if (value <= 3) return { text: '轻微', color: 'green' };
    if (value <= 6) return { text: '中等', color: 'orange' };
    if (value <= 8) return { text: '强烈', color: 'red' };
    return { text: '极致', color: 'purple' };
  };

  const uploadProps = {
    name: 'files',
    action: `${api.defaults.baseURL}/media/upload`, // 媒体文件上传接口
    listType: 'picture-card' as const,
    fileList,
    headers: {
      Authorization: `Bearer ${localStorage.getItem('token')}`
    },
    onChange: ({ fileList: newFileList }: { fileList: UploadFile[] }) => {
      setFileList(newFileList);
    },
    beforeUpload: (file: File) => {
      const isImage = file.type.startsWith('image/');
      const isVideo = file.type.startsWith('video/');
      if (!isImage && !isVideo) {
        message.error('只能上传图片或视频文件！');
        return false;
      }
      const isLt10M = file.size / 1024 / 1024 < 10;
      if (!isLt10M) {
        message.error('文件大小不能超过 10MB！');
        return false;
      }
      return true;
    } };

  return (
    <Modal
      title={
        <div className="flex items-center space-x-2">
          <Smile className="text-primary-500" size={16} />
          <span>创建搞笑恶搞标注</span>
        </div>
      }
      open={isOpen}
      onCancel={handleClose}
      footer={null}
      width={700}
      destroyOnClose
    >
      <div className="space-y-6">
        {/* 位置信息 */}
        <Card size="small" className="bg-blue-50 border-blue-200">
           <div className="flex items-center space-x-2">
             <MapPin className="text-blue-500" size={16} />
             <Text className="text-blue-700">
               点击地图选择位置，或使用默认位置
             </Text>
           </div>
         </Card>

        <Form
          form={form}
          layout="vertical"
          onFinish={handleSubmit}
          initialValues={{
            smell_intensity: 5,
            description: ''
          }}
        >
          {/* 隐藏的位置字段 */}
          <Form.Item name="latitude" hidden>
            <Input />
          </Form.Item>
          <Form.Item name="longitude" hidden>
            <Input />
          </Form.Item>

          {/* 臭味强度 */}
          <Form.Item
            label="臭味强度"
            name="smell_intensity"
            rules={[{ required: true, message: '请选择臭味强度' }]}
          >
            <div className="space-y-4">
              <Slider
                min={1}
                max={10}
                marks={{
                  1: '1',
                  3: '3',
                  5: '5',
                  7: '7',
                  10: '10'
                }}
                tooltip={{
                  formatter: (value) => {
                    const label = getIntensityLabel(value || 5);
                    return `${value} - ${label.text}`;
                  }
                }}
              />
              <Form.Item noStyle shouldUpdate>
                {({ getFieldValue }) => {
                  const intensity = getFieldValue('smell_intensity') || 5;
                  const label = getIntensityLabel(intensity);
                  return (
                    <div className="text-center">
                      <Tag color={label.color} className="text-lg px-4 py-1">
                        {intensity}/10 - {label.text}
                      </Tag>
                    </div>
                  );
                }}
              </Form.Item>
            </div>
          </Form.Item>

          {/* 描述 */}
          <Form.Item
            label="搞笑描述"
            name="description"
            rules={[
              { required: true, message: '请输入搞笑描述' },
              { min: 5, message: '描述至少5个字符' },
              { max: 500, message: '描述不能超过500个字符' }
            ]}
          >
            <TextArea
              rows={4}
              placeholder="描述一下这个地方的搞笑臭味，让大家开心一下吧！\n例如：这里有一股神秘的臭豆腐味道，路过的人都忍不住捂鼻子..."
              showCount
              maxLength={500}
            />
          </Form.Item>

          {/* 媒体上传 */}
          <Form.Item label="上传图片/视频（可选）">
            <Upload {...uploadProps}>
              {fileList.length < 3 && (
                <div className="text-center p-4">
                  <Camera className="text-2xl text-gray-400 mb-2" size={24} />
                  <div className="text-gray-600">点击上传</div>
                  <div className="text-xs text-gray-400">支持图片/视频，最多3个文件</div>
                </div>
              )}
            </Upload>
          </Form.Item>

          {/* 提交按钮 */}
          <Form.Item>
            <Row gutter={16}>
              <Col span={12}>
                <Button block onClick={handleClose}>
                  取消
                </Button>
              </Col>
              <Col span={12}>
                <Button 
                  type="primary" 
                  htmlType="submit" 
                  loading={loading}
                  block
                  className="bg-gradient-to-r from-primary-500 to-secondary-500"
                >
                  创建恶搞标注
                </Button>
              </Col>
            </Row>
          </Form.Item>
        </Form>

        {/* 温馨提示 */}
        <Card size="small" className="bg-yellow-50 border-yellow-200">
          <Text className="text-yellow-700 text-sm">
            💡 温馨提示：请确保内容健康有趣，不要发布不当信息。我们会对所有标注进行审核。
          </Text>
        </Card>
      </div>
    </Modal>
  );
};

export default PrankCreateModal;