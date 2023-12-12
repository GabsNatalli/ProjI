import bcrypt
from fastapi import APIRouter, Depends, Form, Path, Query, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from models.Usuario import Usuario
from repositories.ProdutoRepo import ProdutoRepo
from repositories.UsuarioRepo import UsuarioRepo
from util.mensagem import adicionar_cookie_mensagem, redirecionar_com_mensagem
from util.seguranca import (
    adicionar_cookie_autenticacao,
    conferir_senha,
    excluir_cookie_autenticacao,
    gerar_token,
    obter_usuario_logado,
    obter_hash_senha,
)

router = APIRouter()
templates = Jinja2Templates(directory="templates")


@router.get("/", response_class=HTMLResponse)
async def get_index(
    request: Request,
    usuario: Usuario = Depends(obter_usuario_logado),
):
    produtos = ProdutoRepo.obter_todos()

    return templates.TemplateResponse(
        "root/index.html",
        {"request": request, "usuario": usuario, "produtos": produtos},
    )


@router.get("/login", response_class=HTMLResponse)
async def get_login(
    request: Request,
    usuario: Usuario = Depends(obter_usuario_logado),
):
    return templates.TemplateResponse(
        "root/login.html",
        {"request": request, "usuario": usuario},
    )


@router.post("/login", response_class=RedirectResponse)
async def post_login(
    email: str = Form(...),
    senha: str = Form(...),
    return_url: str = Query("/"),
):
    hash_senha_bd = UsuarioRepo.obter_senha_por_email(email)
    if conferir_senha(senha, hash_senha_bd):
        token = gerar_token()
        UsuarioRepo.alterar_token_por_email(token, email)
        response = RedirectResponse(return_url, status.HTTP_302_FOUND)
        adicionar_cookie_autenticacao(response, token)
        adicionar_cookie_mensagem(response, "Login realizado com sucesso.")
    else:
        response = redirecionar_com_mensagem(
            "/login",
            "Credenciais inválidas. Tente novamente.",
        )
    return response


@router.get("/logout")
async def get_logout(usuario: Usuario = Depends(obter_usuario_logado)):
    if usuario:
        UsuarioRepo.alterar_token_por_email("", usuario.email)
        response = RedirectResponse("/", status.HTTP_302_FOUND)
        excluir_cookie_autenticacao(response)
        adicionar_cookie_mensagem(response, "Saída realizada com sucesso.")
        return response


@router.get("/detalhes/{id_produto:int}")
async def get_detalhes(
    request: Request,
    id_produto: int = Path(),
    usuario: Usuario = Depends(obter_usuario_logado),
):
    produto = ProdutoRepo.obter_por_id(id_produto)

    return templates.TemplateResponse(
        "root/detalhes.html",
        {"request": request, "usuario": usuario, "produto": produto},
    )


@router.get("/cadastro")
async def get_cadastro(
    request: Request,
):
    return templates.TemplateResponse(
        "root/cadastro.html",
        {
            "request": request,
        },
    )


@router.post("/cadastro")
async def post_cadastro(
    nome: str = Form(...),
    email: str = Form(...),
    senha: str = Form(...),
):
    hash = obter_hash_senha(senha)
    usuario = Usuario(nome=nome, email=email, senha=hash)
    usuario = UsuarioRepo.inserir(usuario)

    response = redirecionar_com_mensagem("/", "Usuário cadastrado com sucesso!")
    return response


@router.get("/restrito")
async def get_restrito(
    request: Request,
    usuario_logado: Usuario = Depends(obter_usuario_logado),
):
    usuario = UsuarioRepo.obter_por_id(usuario_logado.id)

    return templates.TemplateResponse(
        "root/restrito.html",
        {"request": request, "usuario": usuario},
    )


from fastapi import Form


@router.post("/alterar")
async def post_alterar_perfil(
    nome: str = Form(...),
    email: str = Form(...),
    usuario_logado: Usuario = Depends(obter_usuario_logado),
):
    usuario_logado.nome = nome
    usuario_logado.email = email
    UsuarioRepo.alterar(usuario_logado)

    response = redirecionar_com_mensagem("/", "Usuário cadastrado com sucesso!")
    return response


@router.post("/altsenha")
async def post_alterar_senha(
    request: Request,
    senha_atual: str = Form(...),
    nova_senha: str = Form(...),
    conf_nova_senha: str = Form(...),
    usuario_logado: Usuario = Depends(obter_usuario_logado),
):
    if not conferir_senha(usuario_logado.senha, senha_atual):
        return templates.TemplateResponse(
            "root/restrito.html",  # Corrija o nome do template aqui
            {
                "request": request,
                "usuario": usuario_logado,
                "erro_senha": "Senha atual incorreta.",
            },
        )

    if nova_senha != conf_nova_senha:
        return templates.TemplateResponse(
            "root/restrito.html",
            {
                "request": request,
                "usuario": usuario_logado,
                "erro_senha": "As novas senhas não coincidem.",
            },
        )

    usuario_logado.senha = obter_hash_senha(nova_senha)
    UsuarioRepo.atualizar_senha(usuario_logado)

    return templates.TemplateResponse(
        "root/restrito.html",
        {
            "request": request,
            "usuario": usuario_logado,
            "mensagem_senha": "Senha atualizada com sucesso.",
        },
    )


@router.get("/historico", response_class=HTMLResponse)
async def get_historico(
    request: Request,
    usuario: Usuario = Depends(obter_usuario_logado),
):
    return templates.TemplateResponse(
        "root/historico.html",
        {"request": request, "usuario": usuario},
    )


@router.get("/fechamentoCompra", response_class=HTMLResponse)
async def get_historico(
    request: Request,
    usuario: Usuario = Depends(obter_usuario_logado),
):
    return templates.TemplateResponse(
        "root/fechamentoCompra.html",
        {"request": request, "usuario": usuario},
    )


@router.get("/restrito")
async def get_restrito(
    request: Request,
    usuario_logado: Usuario = Depends(obter_usuario_logado),
):
    usuario = UsuarioRepo.obter_por_id(usuario_logado.id)

    return templates.TemplateResponse(
        "root/restrito.html",
        {"request": request, "usuario": usuario},
    )


@router.get("/politicaP")
async def get_politicaP(
    request: Request,
):
    return templates.TemplateResponse(
        "root/politicaP.html",
        {
            "request": request,
        },
    )


@router.get("/termosP")
async def get_termosP(
    request: Request,
):
    return templates.TemplateResponse(
        "root/termosP.html",
        {
            "request": request,
        },
    )
