package localtypes

type Result[T any] interface {
	GetValue() T
	GetError() error
}

type Error[T any] struct {
	Err error
}

func (r *Error[T]) GetValue() T {
	panic(r.Err.Error())
}

func (r *Error[T]) GetError() error {
	return r.Err
}

type Value[T any] struct {
	Value T
}

func (r *Value[T]) GetValue() T {
	return r.Value
}

func (r *Value[T]) GetError() error {
	return nil
}
