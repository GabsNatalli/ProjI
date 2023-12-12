from fastapi import (
    APIRouter,
    Depends,
    Form,
    HTTPException,
    Path,
    Request,
    status,
)
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from models.Usuario import Usuario
from repositories.UsuarioRepo import UsuarioRepo
from util.mensagem import redirecionar_com_mensagem
from util.seguranca import obter_usuario_logado

router = APIRouter(prefix="/usuario")
templates = Jinja2Templates(directory="templates")


@router.get("/", response_class=HTMLResponse)
async def get_index(
    request: Request,
    usuario: Usuario = Depends(obter_usuario_logado),
):
    if not usuario:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)
    if not usuario.admin:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)

    usuarios = UsuarioRepo.obter_todos()

    return templates.TemplateResponse(
        "usuario/index.html",
        {"request": request, "usuario": usuario, "usuarios": usuarios},
    )


@router.get("/excluir/{id_usuario:int}", response_class=HTMLResponse)
async def get_excluir(
    request: Request,
    id_usuario: int = Path(),
    usuario: Usuario = Depends(obter_usuario_logado),
):
    if not usuario:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)
    if not usuario.admin:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)

    usuario_excluir = UsuarioRepo.obter_por_id(id_usuario)

    return templates.TemplateResponse(
        "usuario/excluir.html",
        {"request": request, "usuario": usuario, "usuario_excluir": usuario_excluir},
    )


@router.post("/excluir/{id_usuario:int}", response_class=HTMLResponse)
async def post_excluir(
    usuario: Usuario = Depends(obter_usuario_logado),
    id_usuario: int = Path(),
):
    if not usuario:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)
    if not usuario.admin:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)

    if id_usuario == 1:
        response = redirecionar_com_mensagem(
            "/usuario",
            "Não é possível excluir o administrador padrão do sistema.",
        )
        return response

    if id_usuario == usuario.id:
        response = redirecionar_com_mensagem(
            "/usuario",
            "Não é possível excluir o próprio usuário que está logado.",
        )
        return response

    UsuarioRepo.excluir(id_usuario)

    response = redirecionar_com_mensagem(
        "/usuario",
        "Usuário excluído com sucesso.",
    )
    return response


@router.get("/alterar/{id_usuario:int}", response_class=HTMLResponse)
async def get_alterar(
    request: Request,
    id_usuario: int = Path(),
    usuario: Usuario = Depends(obter_usuario_logado),
):
    if not usuario:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)
    if not usuario.admin:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)

    usuario_alterar = UsuarioRepo.obter_por_id(id_usuario)

    return templates.TemplateResponse(
        "usuario/alterar.html",
        {"request": request, "usuario": usuario, "usuario_alterar": usuario_alterar},
    )


@router.post("/alterar/{id_usuario:int}", response_class=HTMLResponse)
async def post_alterar(
    id_usuario: int = Path(),
    nome: str = Form(...),
    email: str = Form(...),
    administrador: bool = Form(False),
    usuario: Usuario = Depends(obter_usuario_logado),
):
    if not usuario:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)
    if not usuario.admin:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)

    if id_usuario == 1:
        response = redirecionar_com_mensagem(
            "/usuario",
            "Não é possível alterar dados do administrador padrão.",
        )
        return response

    UsuarioRepo.alterar(
        Usuario(id=id_usuario, nome=nome, email=email, admin=administrador)
    )

    response = redirecionar_com_mensagem(
        "/usuario",
        "Usuário alterado com sucesso.",
    )

    return response


@router.post("/alterar-senha/{id_usuario:int}", response_model=bool)
async def post_alterar_senha(
    id_usuario: int,
    senha_atual: str,  # Receber a senha atual do formulário
    nova_senha: str,  # Receber a nova senha do formulário
    usuario: Usuario = Depends(obter_usuario_logado),
):
    # Verificar se o usuário está autenticado
    if not usuario:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)

    # Verificar se o usuário tem permissão para alterar essa senha (caso necessário)
    # Isso pode depender da lógica do seu sistema (se todos os usuários podem alterar sua própria senha, por exemplo)

    # Verificar se a senha atual do usuário é correta (consultando o banco de dados)
    senha_atual_correta = UsuarioRepo.verificar_senha_atual(id_usuario, senha_atual)

    if not senha_atual_correta:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Senha atual incorreta"
        )

    # Atualizar a senha do usuário no banco de dados
    senha_hash = UsuarioRepo.hash_senha(nova_senha)  # Hash da nova senha
    alteracao_feita = UsuarioRepo.alterar_senha(id_usuario, senha_hash)

    if not alteracao_feita:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Erro ao alterar a senha",
        )

    return True  # Indicando que a senha foi alterada com sucesso
