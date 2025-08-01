package op

import (
	"fmt"
	"github.com/alist-org/alist/v3/internal/db"
	"github.com/alist-org/alist/v3/internal/model"
	"github.com/pkg/errors"
	"strconv"
	"strings"
	"time"
)

type CreateLabelFileBinDingReq struct {
	Id          string    `json:"id"`
	Path        string    `json:"path"`
	Name        string    `json:"name"`
	Size        int64     `json:"size"`
	IsDir       bool      `json:"is_dir"`
	Modified    time.Time `json:"modified"`
	Created     time.Time `json:"created"`
	Sign        string    `json:"sign"`
	Thumb       string    `json:"thumb"`
	Type        int       `json:"type"`
	HashInfoStr string    `json:"hashinfo"`
	LabelIds    string    `json:"label_ids"`
}

type ObjLabelResp struct {
	Id          string        `json:"id"`
	Path        string        `json:"path"`
	Name        string        `json:"name"`
	Size        int64         `json:"size"`
	IsDir       bool          `json:"is_dir"`
	Modified    time.Time     `json:"modified"`
	Created     time.Time     `json:"created"`
	Sign        string        `json:"sign"`
	Thumb       string        `json:"thumb"`
	Type        int           `json:"type"`
	HashInfoStr string        `json:"hashinfo"`
	LabelList   []model.Label `json:"label_list"`
}

func GetLabelByFileName(userId uint, fileName string) ([]model.Label, error) {
	labelIds, err := db.GetLabelIds(userId, fileName)
	if err != nil {
		return nil, errors.WithMessage(err, "failed get label_file_binding")
	}
	var labels []model.Label
	if len(labelIds) > 0 {
		if labels, err = db.GetLabelByIds(labelIds); err != nil {
			return nil, errors.WithMessage(err, "failed labels in database")
		}
	}
	return labels, nil
}

func CreateLabelFileBinDing(req CreateLabelFileBinDingReq, userId uint) error {
	if err := db.DelLabelFileBinDingByFileName(userId, req.Name); err != nil {
		return errors.WithMessage(err, "failed del label_file_bin_ding in database")
	}
	if req.LabelIds == "" {
		return nil
	}
	labelMap := strings.Split(req.LabelIds, ",")
	for _, value := range labelMap {
		labelId, err := strconv.ParseUint(value, 10, 64)
		if err != nil {
			return fmt.Errorf("invalid label ID '%s': %v", value, err)
		}
		if err = db.CreateLabelFileBinDing(req.Name, uint(labelId), userId); err != nil {
			return errors.WithMessage(err, "failed labels in database")
		}
	}
	if !db.GetFileByNameExists(req.Name) {
		objFile := model.ObjFile{
			Id:          req.Id,
			UserId:      userId,
			Path:        req.Path,
			Name:        req.Name,
			Size:        req.Size,
			IsDir:       req.IsDir,
			Modified:    req.Modified,
			Created:     req.Created,
			Sign:        req.Sign,
			Thumb:       req.Thumb,
			Type:        req.Type,
			HashInfoStr: req.HashInfoStr,
		}
		err := db.CreateObjFile(objFile)
		if err != nil {
			return errors.WithMessage(err, "failed file in database")
		}
	}
	return nil
}

func GetFileByLabel(userId uint, labelId string) (result []ObjLabelResp, err error) {
	labelMap := strings.Split(labelId, ",")
	var labelIds []uint
	var labelsFile []model.LabelFileBinDing
	var labels []model.Label
	var labelsFileMap = make(map[string][]model.Label)
	var labelsMap = make(map[uint]model.Label)
	if labelIds, err = StringSliceToUintSlice(labelMap); err != nil {
		return nil, errors.WithMessage(err, "failed string to uint err")
	}
	//查询标签信息
	if labels, err = db.GetLabelByIds(labelIds); err != nil {
		return nil, errors.WithMessage(err, "failed labels in database")
	}
	for _, val := range labels {
		labelsMap[val.ID] = val
	}
	//查询标签对应文件名列表
	if labelsFile, err = db.GetLabelFileBinDingByLabelId(labelIds, userId); err != nil {
		return nil, errors.WithMessage(err, "failed labels in database")
	}
	for _, value := range labelsFile {
		var labelTemp model.Label
		labelTemp = labelsMap[value.LabelId]
		labelsFileMap[value.FileName] = append(labelsFileMap[value.FileName], labelTemp)
	}
	for index, v := range labelsFileMap {
		objFile, err := db.GetFileByName(index, userId)
		if err != nil {
			return nil, errors.WithMessage(err, "failed GetFileByName in database")
		}
		objLabel := ObjLabelResp{
			Id:          objFile.Id,
			Path:        objFile.Path,
			Name:        objFile.Name,
			Size:        objFile.Size,
			IsDir:       objFile.IsDir,
			Modified:    objFile.Modified,
			Created:     objFile.Created,
			Sign:        objFile.Sign,
			Thumb:       objFile.Thumb,
			Type:        objFile.Type,
			HashInfoStr: objFile.HashInfoStr,
			LabelList:   v,
		}
		result = append(result, objLabel)
	}
	return result, nil
}

func StringSliceToUintSlice(strSlice []string) ([]uint, error) {
	uintSlice := make([]uint, len(strSlice))
	for i, str := range strSlice {
		// 使用strconv.ParseUint将字符串转换为uint64
		uint64Value, err := strconv.ParseUint(str, 10, 64)
		if err != nil {
			return nil, err // 如果转换失败，返回错误
		}
		// 将uint64值转换为uint（注意：这里可能存在精度损失，如果uint64值超出了uint的范围）
		uintSlice[i] = uint(uint64Value)
	}
	return uintSlice, nil
}
